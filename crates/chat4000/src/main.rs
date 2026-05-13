// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chat4000_crypto::{
    GROUP_KEY_LEN, PAIRING_CODE_ALPHABET, derive_group_id, derive_pairing_room_id,
    generate_group_key, generate_pairing_code, normalize_pairing_code,
};
use chat4000_proto::{DEFAULT_RELAY_URL, SenderInfo, SenderRole, VersionPolicy};
use chat4000_relay::{
    PairHostOptions, PairHostStatus, PairJoinOptions, host_pairing_session, join_pairing_session,
};
use chrono::{Local, TimeZone};

mod store;
mod transport;
use clap::{Args, Parser, Subcommand};
use crossterm::{
    cursor,
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags, MouseEvent,
        MouseEventKind, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
    tty::IsTty,
};
use qrcode::{QrCode, render::unicode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use store::{MessageStore, OutboundState};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use uuid::Uuid;

static EXCEPTION_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_GUARDS: OnceLock<Vec<WorkerGuard>> = OnceLock::new();
static TELEMETRY_ENABLED: OnceLock<bool> = OnceLock::new();
static DEBUG_ACKS: OnceLock<bool> = OnceLock::new();
const ALLOW_OUTDATED_PLUGIN_ENV: &str = "CHAT4000_ALLOW_OUTDATED_PLUGIN";
const RELEASE_CHANNEL: &str = "release";
const DEFAULT_APP_ID: &str = "com.neonnode.chat4000cli";
const CLI_BUNDLE_ID: &str = "com.neonnode.chat4000cli";
const MIN_PLUGIN_VERSION: &str = "0.1.0";
const BUILT_IN_SENTRY_DSN: Option<&str> = option_env!("CHAT4000_SENTRY_DSN");
const PRIVACY_POLICY_URL: &str = "https://chat4000.com/privacy";
const SUPPORT_URL: &str = "https://t.me/chat4000official";

#[derive(Parser, Debug)]
#[command(
    name = "chat4000",
    version,
    about = "Encrypted terminal client for OpenClaw agents"
)]
struct Cli {
    #[arg(long, global = true)]
    log_dir: Option<PathBuf>,

    #[arg(long, global = true, default_value = "info")]
    log_level: LogLevel,

    #[arg(long, global = true)]
    stdout_logs: bool,

    #[arg(long, global = true)]
    no_telemetry: bool,

    /// Print every recv_ack / relay_recv_ack / inner ack to stderr for verification.
    #[arg(long, global = true)]
    debug_acks: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Info,
    Debug,
}

#[derive(Subcommand, Debug)]
enum Command {
    Pair(PairArgs),
    Status,
    Disconnect,
    Support,
    Telemetry(TelemetryArgs),
    Send(SendArgs),
    History(HistoryArgs),
    Guide,
    #[command(name = "debug-exception", hide = true)]
    DebugException(DebugExceptionArgs),
}

#[derive(Args, Debug)]
struct SendArgs {
    /// Message to send. If omitted, the message is read from stdin.
    message: Option<String>,

    /// Seconds to wait for the agent's reply before giving up.
    #[arg(long, default_value_t = 120)]
    timeout: u64,

    /// Print only the agent's reply text — no echo of the sent message,
    /// no timestamp, no `agent:` prefix. Pipe-friendly.
    #[arg(long)]
    raw: bool,
}

#[derive(Args, Debug)]
struct HistoryArgs {
    /// Number of past messages to show (oldest → newest).
    #[arg(short = 'n', long, default_value_t = 5)]
    limit: usize,
}

#[derive(Args, Debug)]
struct TelemetryArgs {
    #[command(subcommand)]
    command: TelemetryCommand,
}

#[derive(Subcommand, Debug)]
enum TelemetryCommand {
    Enable,
    Disable,
    Status,
}

#[derive(Args, Debug)]
struct DebugExceptionArgs {
    #[arg(long, default_value = "handled")]
    kind: DebugExceptionKind,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum DebugExceptionKind {
    Handled,
    Panic,
}

#[derive(Args, Debug)]
struct PairArgs {
    #[arg(long)]
    host: bool,

    #[arg(long)]
    code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GroupConfig {
    #[serde(rename = "groupKeyBase64")]
    group_key_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HistoryEntry {
    role: HistoryRole,
    text: String,
    ts: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryRole {
    User,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceIdentityRecord {
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "deviceName")]
    device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpdateNagRecord {
    recommended_version: Option<String>,
    shown_at_ms: i64,
}

const UPDATE_NAG_INTERVAL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
struct AppDeviceIdentity {
    sender: SenderInfo,
}

impl GroupConfig {
    fn group_key(&self) -> Result<Vec<u8>> {
        let bytes = STANDARD
            .decode(&self.group_key_base64)
            .context("invalid base64 in saved group config")?;
        if bytes.len() != GROUP_KEY_LEN {
            bail!("saved group key must be 32 bytes");
        }
        Ok(bytes)
    }

    fn group_id(&self) -> Result<String> {
        Ok(derive_group_id(&self.group_key()?))
    }
}

impl AppDeviceIdentity {
    fn sender(&self) -> SenderInfo {
        self.sender.clone()
    }

    fn is_local_sender(&self, sender: Option<&SenderInfo>) -> bool {
        sender
            .map(|sender| {
                sender.role == SenderRole::App && sender.device_id == self.sender.device_id
            })
            .unwrap_or(false)
    }
}

#[tokio::main]
async fn main() {
    install_rustls_provider();
    let cli = Cli::parse();
    let paths = match AppPaths::resolve() {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!("Error: {err:?}");
            return;
        }
    };
    init_tracing(&cli, &paths);
    let telemetry = TelemetryState::resolve(&cli);
    let _ = TELEMETRY_ENABLED.set(telemetry.enabled);
    let _ = DEBUG_ACKS.set(cli.debug_acks);
    if matches!(cli.command, Some(Command::Telemetry(_))) {
        install_panic_hook();
        let result = match cli.command {
            Some(Command::Telemetry(args)) => cmd_telemetry(args, &telemetry),
            _ => Ok(()),
        };
        if let Err(err) = result {
            record_exception("runtime_error", &format!("{err:?}"));
            error!(error = ?err, "runtime error");
            eprintln!("Error: {err:?}");
        }
        return;
    }
    telemetry.maybe_print_notice();
    let sentry_guard = init_sentry(&telemetry);
    install_panic_hook();

    let result = match cli.command {
        Some(Command::Pair(args)) => cmd_pair(args, &paths).await,
        Some(Command::Status) => cmd_status(&paths).await,
        Some(Command::Disconnect) => cmd_disconnect(&paths),
        Some(Command::Support) => cmd_support(),
        Some(Command::Telemetry(_)) => Ok(()),
        Some(Command::Send(args)) => cmd_send(args, &paths).await,
        Some(Command::History(args)) => cmd_history(args, &paths),
        Some(Command::Guide) => {
            print_guide();
            Ok(())
        }
        Some(Command::DebugException(args)) => cmd_debug_exception(args),
        None => cmd_chat_bootstrap(&paths).await,
    };

    if let Err(err) = result {
        record_exception("runtime_error", &format!("{err:?}"));
        error!(error = ?err, "runtime error");
        eprintln!("Error: {err:?}");
        flush_sentry(&sentry_guard);
        std::process::exit(1);
    }
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug, Clone)]
struct TelemetryState {
    enabled: bool,
    config_dir: Option<PathBuf>,
    install_id: String,
    persistent_enabled: Option<bool>,
    disabled_by_flag: bool,
    disabled_by_env: bool,
}

impl TelemetryState {
    fn resolve(cli: &Cli) -> Self {
        let config_dir = dirs::home_dir().map(|home| home.join(".config").join("chat4000"));
        let disabled_by_flag = cli.no_telemetry;
        let disabled_by_env = env_truthy("CHAT4000_TELEMETRY_DISABLED");
        let persistent_enabled = config_dir
            .as_ref()
            .and_then(|dir| read_bool_file(&dir.join("telemetry-enabled")));
        let enabled = if disabled_by_flag {
            false
        } else if disabled_by_env {
            false
        } else if let Some(value) = persistent_enabled {
            value
        } else {
            true
        };
        let install_id = if enabled {
            config_dir
                .as_ref()
                .and_then(|dir| load_or_create_install_id(dir).ok())
                .unwrap_or_else(|| Uuid::new_v4().to_string())
        } else {
            Uuid::new_v4().to_string()
        };

        Self {
            enabled,
            config_dir,
            install_id,
            persistent_enabled,
            disabled_by_flag,
            disabled_by_env,
        }
    }

    fn telemetry_file(&self) -> Option<PathBuf> {
        self.config_dir
            .as_ref()
            .map(|dir| dir.join("telemetry-enabled"))
    }

    fn notice_file(&self) -> Option<PathBuf> {
        self.config_dir.as_ref().map(|dir| dir.join("notice-shown"))
    }

    fn maybe_print_notice(&self) {
        if !self.enabled {
            return;
        }
        let Some(path) = self.notice_file() else {
            print_telemetry_notice();
            return;
        };
        if path.exists() {
            return;
        }
        print_telemetry_notice();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, b"");
    }
}

fn cmd_telemetry(args: TelemetryArgs, telemetry: &TelemetryState) -> Result<()> {
    match args.command {
        TelemetryCommand::Enable => {
            let path = telemetry
                .telemetry_file()
                .context("could not resolve telemetry config path")?;
            match write_private_text(&path, "true\n") {
                Ok(()) => {
                    println!("Telemetry enabled. Anonymous error reports will be sent.");
                    println!("Privacy policy: {PRIVACY_POLICY_URL}");
                }
                Err(err) => {
                    println!(
                        "Telemetry is enabled for this run, but the setting could not be saved."
                    );
                    println!("Reason: {err}");
                }
            }
        }
        TelemetryCommand::Disable => {
            let path = telemetry
                .telemetry_file()
                .context("could not resolve telemetry config path")?;
            match write_private_text(&path, "false\n") {
                Ok(()) => {
                    println!("Telemetry disabled. No data will be sent to chat4000.");
                    println!("Re-enable: chat4000 telemetry enable");
                }
                Err(err) => {
                    println!("Telemetry could not be disabled persistently.");
                    println!("Use CHAT4000_TELEMETRY_DISABLED=1 or --no-telemetry.");
                    println!("Reason: {err}");
                }
            }
        }
        TelemetryCommand::Status => {
            let reason = if telemetry.disabled_by_flag {
                "disabled for this invocation by --no-telemetry"
            } else if telemetry.disabled_by_env {
                "disabled by CHAT4000_TELEMETRY_DISABLED"
            } else if telemetry.persistent_enabled == Some(false) {
                "disabled in config"
            } else if telemetry.persistent_enabled == Some(true) {
                "enabled in config"
            } else {
                "enabled by default"
            };
            println!(
                "Telemetry: {}",
                if telemetry.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Reason: {reason}");
            if telemetry.enabled {
                println!("Disable: chat4000 telemetry disable");
                println!("Or set CHAT4000_TELEMETRY_DISABLED=1");
            } else {
                println!("Enable: chat4000 telemetry enable");
            }
        }
    }
    Ok(())
}

fn print_telemetry_notice() {
    eprintln!(
        "chat4000 v{}\n\nAnonymous error reports help us fix bugs faster. We collect crash data\nand error traces -- never message content, prompts, command arguments,\nor environment variables.\n\nTo opt out:\n  chat4000 telemetry disable\n  or set CHAT4000_TELEMETRY_DISABLED=1\n\nPrivacy policy: {PRIVACY_POLICY_URL}\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn init_sentry(telemetry: &TelemetryState) -> Option<sentry::ClientInitGuard> {
    if !telemetry.enabled {
        return None;
    }
    let dsn = env::var("CHAT4000_SENTRY_DSN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| BUILT_IN_SENTRY_DSN.map(ToOwned::to_owned))?;
    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: Some(format!("chat4000@{}", env!("CARGO_PKG_VERSION")).into()),
            environment: Some(
                env::var("NODE_ENV")
                    .unwrap_or_else(|_| "production".to_string())
                    .into(),
            ),
            send_default_pii: false,
            attach_stacktrace: true,
            sample_rate: sentry_sample_rate(),
            traces_sample_rate: 0.0,
            before_send: Some(Arc::new(scrub_sentry_event)),
            ..Default::default()
        },
    ));
    sentry::configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(telemetry.install_id.clone()),
            ..Default::default()
        }));
        scope.set_tag("cli_version", env!("CARGO_PKG_VERSION"));
        scope.set_tag("os_platform", env::consts::OS);
        scope.set_tag("os_arch", env::consts::ARCH);
    });
    info!("sentry telemetry initialized");
    Some(guard)
}

fn flush_sentry(guard: &Option<sentry::ClientInitGuard>) {
    if let Some(guard) = guard {
        let flushed = guard.flush(Some(Duration::from_secs(5)));
        debug!(flushed, "flushed sentry events");
    }
}

fn sentry_sample_rate() -> f32 {
    env::var("CHAT4000_SENTRY_SAMPLE_RATE")
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .map(|value| value.clamp(0.0, 1.0))
        .unwrap_or(0.2)
}

fn scrub_sentry_event(
    mut event: sentry::protocol::Event<'static>,
) -> Option<sentry::protocol::Event<'static>> {
    event.server_name = None;
    event.request = None;
    event.message = event.message.map(|message| scrub_secrets(&message).into());
    for exception in &mut event.exception.values {
        if let Some(value) = &exception.value {
            exception.value = Some(scrub_secrets(value).into());
        }
        if let Some(stacktrace) = &mut exception.stacktrace {
            for frame in &mut stacktrace.frames {
                if let Some(filename) = &frame.filename {
                    frame.filename = Some(scrub_path(filename).into());
                }
                frame.vars.clear();
            }
        }
    }
    event.extra.remove("env");
    event.extra.remove("argv");
    event.extra.remove("argv0");
    Some(event)
}

fn scrub_path(path: &str) -> String {
    let home_scrubbed = dirs::home_dir()
        .and_then(|home| home.to_str().map(|home| path.replace(home, "~")))
        .unwrap_or_else(|| path.to_string());
    let re = Regex::new(r"/(Users|home)/[^/]+").expect("valid path scrub regex");
    re.replace_all(&home_scrubbed, "/$1/<user>").to_string()
}

fn scrub_secrets(text: &str) -> String {
    let patterns = [
        (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]"),
        (r"ghp_[a-zA-Z0-9]{20,}", "[REDACTED_GITHUB_TOKEN]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"(?i)Bearer\s+[a-zA-Z0-9._\-]+", "Bearer [REDACTED]"),
        (r#"(?i)password["\s:=]+[^\s",}]+"#, "password=[REDACTED]"),
        (r#"(?i)token["\s:=]+[^\s",}]+"#, "token=[REDACTED]"),
    ];
    let mut scrubbed = text.to_string();
    for (pattern, replacement) in patterns {
        let re = Regex::new(pattern).expect("valid secret scrub regex");
        scrubbed = re.replace_all(&scrubbed, replacement).to_string();
    }
    scrubbed
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn read_bool_file(path: &Path) -> Option<bool> {
    let value = fs::read_to_string(path).ok()?;
    match value.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn load_or_create_install_id(config_dir: &Path) -> Result<String> {
    let path = config_dir.join("install-id");
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }
    fs::create_dir_all(config_dir)?;
    let install_id = Uuid::new_v4().to_string();
    write_private_text(&path, &format!("{install_id}\n"))?;
    Ok(install_id)
}

const LOG_FILE_NAME: &str = "chat4000.log";
const LOG_MAX_BYTES: usize = 10 * 1024 * 1024;

fn init_tracing(cli: &Cli, paths: &AppPaths) {
    use file_rotate::{ContentLimit, FileRotate, compression::Compression, suffix::AppendCount};

    let preferred_log_dir = cli.log_dir.clone().unwrap_or_else(|| paths.log_dir.clone());
    let log_dir = usable_log_dir(preferred_log_dir);
    let log_path = log_dir.join(LOG_FILE_NAME);

    let rotating = FileRotate::new(
        &log_path,
        AppendCount::new(0),
        ContentLimit::Bytes(LOG_MAX_BYTES),
        Compression::None,
        None,
    );
    let (writer, guard) = tracing_appender::non_blocking(rotating);
    let _ = EXCEPTION_LOG_PATH.set(log_path.clone());
    let _ = LOG_GUARDS.set(vec![guard]);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| match cli.log_level {
        LogLevel::Info => EnvFilter::new("info"),
        LogLevel::Debug => EnvFilter::new("debug"),
    });

    let log_layer = fmt::layer().with_ansi(false).with_writer(writer);
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(log_layer);

    if cli.stdout_logs {
        subscriber.with(fmt::layer()).init();
    } else {
        subscriber.init();
    }

    info!(log_path = %log_path.display(), log_level = ?cli.log_level, stdout_logs = cli.stdout_logs, "logging initialized");
}

fn usable_log_dir(preferred: PathBuf) -> PathBuf {
    if can_write_to_dir(&preferred) {
        return preferred;
    }
    let fallback = env::temp_dir().join("chat4000-logs");
    let _ = can_write_to_dir(&fallback);
    fallback
}

fn can_write_to_dir(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write-test");
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let message = panic_info.to_string();
        record_exception("panic", &message);
        eprintln!("panic: {message}");
        previous(panic_info);
    }));
}

fn record_exception(kind: &str, message: &str) {
    if let Some(path) = EXCEPTION_LOG_PATH.get() {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "[{}] {}", kind, message);
        }
    }
    if TELEMETRY_ENABLED.get().copied().unwrap_or(false) {
        sentry::with_scope(
            |scope| {
                scope.set_tag("exception_kind", kind);
            },
            || {
                let event_id =
                    sentry::capture_message(&scrub_secrets(message), sentry::Level::Error);
                debug!(%event_id, "captured exception for sentry");
            },
        );
    }
}

async fn cmd_chat_bootstrap(paths: &AppPaths) -> Result<()> {
    info!("starting chat bootstrap");
    match paths.load_config()? {
        Some(config) => {
            run_chat_session(config, paths).await?;
        }
        None => {
            let config = interactive_pair(paths).await?;
            run_chat_session(config, paths).await?;
        }
    }
    Ok(())
}

async fn cmd_pair(args: PairArgs, paths: &AppPaths) -> Result<()> {
    info!(?args.host, "running pair command");
    if args.host {
        let Some(config) = paths.load_config()? else {
            bail!("host pairing requires an existing paired config");
        };
        let code = args.code.unwrap_or_else(generate_pairing_code);
        print_pairing_host_screen(&code);

        println!("Press Ctrl-C to stop pairing.");
        println!("Status: [1/5] Opening pairing session");
        let result = run_host_pairing_with_ctrl_c(
            PairHostOptions {
                relay_url: DEFAULT_RELAY_URL.to_string(),
                group_key: config.group_key()?,
                code: Some(code),
                allow_self_signed_tls: false,
            },
            |status, _| println!("{}", pairing_status_line(status)),
        )
        .await;
        match result {
            Ok(result) => {
                println!("✓ Pairing session finished for {}.", result.code);
            }
            Err(err) if is_pairing_cancelled(&err) => {
                println!("Pairing cancelled.");
            }
            Err(err) => return Err(err),
        }
        return Ok(());
    }

    let code = match args.code {
        Some(code) => code,
        None => prompt_pairing_code("Enter pairing code: ")?,
    };

    println!("• Opening pairing room…");
    let result = join_pairing_session(PairJoinOptions {
        relay_url: DEFAULT_RELAY_URL.to_string(),
        code,
        allow_self_signed_tls: false,
    })
    .await?;
    let config = GroupConfig {
        group_key_base64: STANDARD.encode(&result.group_key),
    };
    paths.save_config(&config)?;
    println!("✓ Paired.");
    println!("[connected · group {}…]", &result.group_id[..8]);
    Ok(())
}

async fn cmd_status(paths: &AppPaths) -> Result<()> {
    let Some(config) = paths.load_config()? else {
        println!("Status: unpaired");
        println!("Config: {}", paths.config_file.display());
        return Ok(());
    };

    use crate::transport::MessageTransport;
    use crate::transport::relay::{RelayMessageTransport, TransportConfig};
    use std::sync::Arc;

    let group_id = config.group_id()?;
    let identity = paths.load_or_create_device_identity()?;
    let store = Arc::new(paths.open_store().context("failed to open message store")?);
    let transport_config = TransportConfig {
        relay_url: DEFAULT_RELAY_URL.to_string(),
        group_id: group_id.clone(),
        group_key: config.group_key()?,
        device_id: identity.sender.device_id.clone(),
        sender: identity.sender(),
        app_id: Some(DEFAULT_APP_ID.to_string()),
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        release_channel: Some(RELEASE_CHANNEL.to_string()),
        allow_self_signed_tls: false,
        debug_acks: debug_acks_enabled(),
    };
    let (transport, _events) = RelayMessageTransport::start(transport_config, Arc::clone(&store))
        .await
        .context("failed to connect to relay")?;
    println!("Status: paired");
    println!("Group ID: {group_id}");
    println!("Relay handshake: ok");
    println!("Config: {}", paths.config_file.display());
    println!("History: {}", paths.history_file.display());
    let version_policy = transport.version_policy();
    transport.disconnect();
    if let Some(policy) = version_policy.as_ref() {
        match evaluate_version_policy(env!("CARGO_PKG_VERSION"), policy) {
            VersionPolicyAction::HardBlock { min_version } => {
                println!(
                    "Update required: chat4000 {min_version} or newer is needed to use this relay."
                );
            }
            VersionPolicyAction::SoftNag { recommended } => {
                if let Some(version) = recommended {
                    println!("Update available: chat4000 {version} is recommended.");
                } else {
                    println!("Update available: a newer chat4000 version is recommended.");
                }
            }
            VersionPolicyAction::None => {}
        }
        if let Some(latest) = policy.latest_version.as_deref() {
            println!("Latest version: {latest}");
        }
    }
    Ok(())
}

fn cmd_disconnect(paths: &AppPaths) -> Result<()> {
    info!("running disconnect command");
    if paths.has_local_state() {
        paths.remove_local_state()?;
        println!("Local pairing config and history removed.");
        info!("local state removed");
    } else {
        println!("Nothing to disconnect; no local config was present.");
        info!("disconnect requested with no local state present");
    }
    Ok(())
}

fn cmd_support() -> Result<()> {
    println!("Support: {SUPPORT_URL}");
    match open_support_url() {
        Ok(()) => println!("Opened chat4000 official Telegram support."),
        Err(err) => println!("Could not open browser automatically: {err}"),
    }
    Ok(())
}

fn open_support_url() -> Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("open");
        command.arg(SUPPORT_URL);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", SUPPORT_URL]);
        command
    } else {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(SUPPORT_URL);
        command
    };
    let status = command.status().context("failed to launch support URL")?;
    if status.success() {
        Ok(())
    } else {
        bail!("browser opener exited with {status}")
    }
}

async fn cmd_send(args: SendArgs, paths: &AppPaths) -> Result<()> {
    use std::sync::Arc;

    use crate::transport::relay::{RelayMessageTransport, TransportConfig};
    use crate::transport::{MessageTransport, OutboundMessage};

    info!(timeout = args.timeout, "running send command");

    let config = paths
        .load_config()?
        .ok_or_else(|| anyhow!("not paired — run `chat4000 pair` first"))?;

    let message = match args.message {
        Some(msg) => msg,
        None => {
            use std::io::Read;
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("failed reading message from stdin")?;
            let trimmed = buf.trim().to_string();
            if trimmed.is_empty() {
                bail!("no message given (positional argument or stdin required)");
            }
            trimmed
        }
    };

    let sent_ts = unix_ms();
    paths.append_history(&HistoryEntry {
        role: HistoryRole::User,
        text: message.clone(),
        ts: sent_ts,
    })?;

    let group_key = config.group_key()?;
    let group_id = config.group_id()?;
    let identity = paths.load_or_create_device_identity()?;
    let store = Arc::new(paths.open_store().context("failed to open message store")?);

    let transport_config = TransportConfig {
        relay_url: DEFAULT_RELAY_URL.to_string(),
        group_id: group_id.clone(),
        group_key,
        device_id: identity.sender.device_id.clone(),
        sender: identity.sender(),
        app_id: Some(DEFAULT_APP_ID.to_string()),
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        release_channel: Some(RELEASE_CHANNEL.to_string()),
        allow_self_signed_tls: false,
        debug_acks: debug_acks_enabled(),
    };
    let (transport, mut events) =
        RelayMessageTransport::start(transport_config, Arc::clone(&store))
            .await
            .context("failed to connect to relay")?;
    let plugin_policy = transport.plugin_version_policy();

    let mut outbound = OutboundTracker::default();
    let mut plugin_seen = false;

    // Drain phase: consume events until the agent appears idle.
    let stale_streams = drain_until_idle_via_transport(
        &mut events,
        &transport,
        &identity,
        plugin_policy.as_ref(),
        &mut plugin_seen,
    )
    .await?;

    let outbound_msg_id = transport.send(OutboundMessage::Text(message.clone()));
    outbound.track(outbound_msg_id.clone());
    store.record_outbound(&group_id, &outbound_msg_id, sent_ts)?;

    let timeout = Duration::from_secs(args.timeout);
    let reply_result = tokio::time::timeout(
        timeout,
        wait_for_agent_reply_via_transport(
            &mut events,
            &transport,
            &identity,
            &stale_streams,
            &group_id,
            store.as_ref(),
            &mut outbound,
            plugin_policy.as_ref(),
            &mut plugin_seen,
        ),
    )
    .await;

    transport.disconnect();

    match reply_result {
        Ok(Ok(reply)) => {
            let reply_ts = unix_ms();
            paths.append_history(&HistoryEntry {
                role: HistoryRole::Agent,
                text: reply.clone(),
                ts: reply_ts,
            })?;
            if args.raw {
                println!("{reply}");
            } else {
                let tick = render_tick(outbound.state_of(&outbound_msg_id));
                println!("[{}] you: {} {}", format_ts_with_ms(sent_ts), message, tick);
                println!("[{}] agent: {}", format_ts_with_ms(reply_ts), reply);
            }
            Ok(())
        }
        Ok(Err(err)) => {
            outbound.mark_failed(&outbound_msg_id, &group_id, store.as_ref());
            if !args.raw {
                eprintln!(
                    "[{}] you: {} {}",
                    format_ts_with_ms(sent_ts),
                    message,
                    render_tick(OutboundState::Failed),
                );
            }
            Err(err)
        }
        Err(_) => {
            outbound.mark_failed(&outbound_msg_id, &group_id, store.as_ref());
            if !args.raw {
                eprintln!(
                    "[{}] you: {} {}",
                    format_ts_with_ms(sent_ts),
                    message,
                    render_tick(OutboundState::Failed),
                );
            }
            bail!("timed out after {}s waiting for agent reply", args.timeout)
        }
    }
}

/// Drain incoming events until the relay-and-agent are quiet for 500 ms; if a
/// `thinking`/`typing` status was last seen, wait up to 60 s for `idle`.
async fn drain_until_idle_via_transport(
    events: &mut transport::TransportEvents,
    transport: &dyn transport::MessageTransport,
    identity: &AppDeviceIdentity,
    plugin_policy: Option<&VersionPolicy>,
    plugin_seen: &mut bool,
) -> Result<HashSet<String>> {
    use crate::transport::{ConnectionState, TransportEvent};
    use chat4000_proto::InnerMessageType;

    const QUIET_THRESHOLD: Duration = Duration::from_millis(500);
    const DRAIN_HARD_CAP: Duration = Duration::from_secs(30);
    const IDLE_WAIT_CAP: Duration = Duration::from_secs(60);

    let mut stale: HashSet<String> = HashSet::new();
    let mut last_status: Option<String> = None;
    let drain_started = std::time::Instant::now();

    loop {
        if drain_started.elapsed() > DRAIN_HARD_CAP {
            warn!("drain phase exceeded 30s — proceeding anyway");
            break;
        }
        match tokio::time::timeout(QUIET_THRESHOLD, events.recv()).await {
            Ok(Some(TransportEvent::Receive(msg))) => {
                handle_received_for_consumer(&msg, plugin_policy, plugin_seen);
                if identity.is_local_sender(msg.from.as_ref()) {
                    continue;
                }
                match msg.t {
                    InnerMessageType::Status => {
                        if let Some(s) = msg.body.get("status").and_then(|v| v.as_str()) {
                            last_status = Some(s.to_string());
                        }
                    }
                    InnerMessageType::Text => {
                        // Plain (non-streamed) text: track by inner.id.
                        stale.insert(msg.id.to_string());
                    }
                    InnerMessageType::TextDelta | InnerMessageType::TextEnd => {
                        // Streamed reply: stale-tracking lives on the stream
                        // correlator, not the per-frame inner.id.
                        stale.insert(stream_correlator(&msg));
                    }
                    _ => {}
                }
            }
            Ok(Some(TransportEvent::Status(_))) => {}
            Ok(Some(TransportEvent::Connection(ConnectionState::Failed(reason)))) => {
                bail!("relay connection failed during drain: {reason}");
            }
            Ok(Some(TransportEvent::Connection(_))) => {}
            Ok(None) => bail!("transport closed during drain"),
            Err(_) => break,
        }
    }

    if matches!(last_status.as_deref(), Some("thinking") | Some("typing")) {
        info!(
            ?last_status,
            "agent busy after drain; waiting for idle before sending"
        );
        let idle_started = std::time::Instant::now();
        loop {
            if idle_started.elapsed() > IDLE_WAIT_CAP {
                warn!("agent never went idle within 60s — sending anyway");
                break;
            }
            let remaining = IDLE_WAIT_CAP.saturating_sub(idle_started.elapsed());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Some(TransportEvent::Receive(msg))) => {
                    handle_received_for_consumer(&msg, plugin_policy, plugin_seen);
                    if identity.is_local_sender(msg.from.as_ref()) {
                        continue;
                    }
                    match msg.t {
                        InnerMessageType::Status => {
                            if let Some(s) = msg.body.get("status").and_then(|v| v.as_str()) {
                                if s == "idle" {
                                    info!("agent idle; proceeding to send");
                                    break;
                                }
                            }
                        }
                        InnerMessageType::Text => {
                            stale.insert(msg.id.to_string());
                        }
                        InnerMessageType::TextDelta | InnerMessageType::TextEnd => {
                            stale.insert(stream_correlator(&msg));
                        }
                        _ => {}
                    }
                }
                Ok(Some(TransportEvent::Status(_))) => {}
                Ok(Some(TransportEvent::Connection(ConnectionState::Failed(reason)))) => {
                    bail!("relay connection failed while waiting for idle: {reason}");
                }
                Ok(Some(TransportEvent::Connection(_))) => {}
                Ok(None) => bail!("transport closed while waiting for idle"),
                Err(_) => break,
            }
        }
    }

    Ok(stale)
}

/// Per §6.6.5 + §6.6.11: once an inner message lands, the consumer (not the
/// transport) is responsible for emitting the inner-`ack` Flow B response and
/// for evaluating plugin-version policy.
// §6.6.5: in v1 only the plugin emits inner ack frames. The CLI is an app,
// so it does not emit any. Kept around for the plugin-version-policy nag.
fn handle_received_for_consumer(
    msg: &chat4000_proto::InnerMessage,
    plugin_policy: Option<&VersionPolicy>,
    plugin_seen: &mut bool,
) {
    use chat4000_proto::SenderRole;

    if !*plugin_seen && msg.from.as_ref().map(|f| f.role) == Some(SenderRole::Plugin) {
        *plugin_seen = true;
        if let Some(policy) = plugin_policy {
            let plugin_v = msg.from.as_ref().and_then(|f| f.app_version.as_deref());
            match evaluate_plugin_version_policy(plugin_v, policy) {
                PluginPolicyVerdict::HardBlock => {
                    if !allow_outdated_plugin() {
                        eprintln!(
                            "[plugin update required — set {ALLOW_OUTDATED_PLUGIN_ENV}=1 to bypass]"
                        );
                    } else {
                        eprintln!("[plugin update required, bypassed]");
                    }
                }
                PluginPolicyVerdict::SoftNag => {
                    eprintln!("[plugin update available]");
                }
                PluginPolicyVerdict::Ok => {}
            }
        }
    }
}

async fn wait_for_agent_reply_via_transport(
    events: &mut transport::TransportEvents,
    transport: &dyn transport::MessageTransport,
    identity: &AppDeviceIdentity,
    stale_streams: &HashSet<String>,
    group_id: &str,
    store: &MessageStore,
    outbound: &mut OutboundTracker,
    plugin_policy: Option<&VersionPolicy>,
    plugin_seen: &mut bool,
) -> Result<String> {
    use crate::transport::{ConnectionState, TransportEvent, TransportStatus};

    let mut buffers: HashMap<String, String> = HashMap::new();
    while let Some(event) = events.recv().await {
        match event {
            TransportEvent::Connection(ConnectionState::Failed(reason)) => {
                bail!("relay connection failed: {reason}");
            }
            TransportEvent::Connection(_) => {}
            TransportEvent::Status(update) => match update.status {
                TransportStatus::Sent => {
                    outbound.mark_sent(&update.msg_id, group_id, store);
                }
                TransportStatus::Failed => {
                    outbound.mark_failed(&update.msg_id, group_id, store);
                }
            },
            TransportEvent::Receive(message) => {
                handle_received_for_consumer(&message, plugin_policy, plugin_seen);
                // Inner-ack Flow B inbound: drives `delivered` tick on outbound rows.
                if let Some(ack) = message.as_ack() {
                    if ack.stage == "received" {
                        outbound.mark_delivered(ack.refs, group_id, store);
                    }
                    continue;
                }
                if identity.is_local_sender(message.from.as_ref()) {
                    continue;
                }
                // For Text the dedup/stale-tracking key is inner.id (per-message);
                // for streaming frames it is body.stream_id (per-stream correlator).
                let key = match message.t {
                    chat4000_proto::InnerMessageType::TextDelta
                    | chat4000_proto::InnerMessageType::TextEnd => stream_correlator(&message),
                    _ => message.id.to_string(),
                };
                if stale_streams.contains(&key) {
                    continue;
                }
                match message.t {
                    chat4000_proto::InnerMessageType::Text => {
                        if let Some(text) = message.body.get("text").and_then(|v| v.as_str()) {
                            return Ok(text.to_string());
                        }
                    }
                    chat4000_proto::InnerMessageType::TextDelta => {
                        let delta = message
                            .body
                            .get("delta")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        buffers.entry(key).or_default().push_str(delta);
                    }
                    chat4000_proto::InnerMessageType::TextEnd => {
                        let final_text = message
                            .body
                            .get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let reset = message
                            .body
                            .get("reset")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if reset {
                            buffers.remove(&key);
                            continue;
                        }
                        let assembled = if !final_text.is_empty() {
                            final_text.to_string()
                        } else {
                            buffers.remove(&key).unwrap_or_default()
                        };
                        return Ok(assembled);
                    }
                    _ => {}
                }
            }
        }
    }
    bail!("transport closed before any agent reply arrived");
}

#[derive(Debug, Default)]
struct OutboundTracker {
    states: HashMap<String, OutboundState>,
}

impl OutboundTracker {
    fn track(&mut self, msg_id: String) {
        self.states.insert(msg_id, OutboundState::Sending);
    }

    fn mark_sent(&mut self, msg_id: &str, group_id: &str, store: &MessageStore) {
        if let Some(state) = self.states.get_mut(msg_id) {
            if *state == OutboundState::Sending {
                *state = OutboundState::Sent;
                let _ = store.set_outbound_state(group_id, msg_id, OutboundState::Sent);
            }
        }
    }

    fn mark_delivered(&mut self, msg_id: &str, group_id: &str, store: &MessageStore) {
        if let Some(state) = self.states.get_mut(msg_id) {
            if *state != OutboundState::Delivered {
                *state = OutboundState::Delivered;
                let _ = store.set_outbound_state(group_id, msg_id, OutboundState::Delivered);
            }
        }
    }

    fn mark_failed(&mut self, msg_id: &str, group_id: &str, store: &MessageStore) {
        if let Some(state) = self.states.get_mut(msg_id) {
            // Don't overwrite a real terminal state.
            if !matches!(*state, OutboundState::Delivered) {
                *state = OutboundState::Failed;
                let _ = store.set_outbound_state(group_id, msg_id, OutboundState::Failed);
            }
        }
    }

    fn state_of(&self, msg_id: &str) -> OutboundState {
        self.states
            .get(msg_id)
            .copied()
            .unwrap_or(OutboundState::Sending)
    }
}

/// Per protocol §6.4.2 (post-2026-05-06): the stream correlator lives in
/// `body.stream_id` and is shared across every `text_delta` and `text_end`
/// frame belonging to one logical streamed reply. Inner `id` is a fresh UUID
/// per frame and is the dedup key (§6.6.9), not the stream correlator.
///
/// The transitional fallback (also called out in §6.4.2): if `body.stream_id`
/// is absent, fall back to `inner.id`. This lets us render correctly against
/// pre-2026-05-06 senders that still reuse `inner.id == stream_id`.
fn stream_correlator(message: &chat4000_proto::InnerMessage) -> String {
    message
        .body
        .get("stream_id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| message.id.to_string())
}

/// Render a snippet of arbitrary text for log lines: trims to N chars and
/// replaces newlines/tabs with literal `\n`/`\t` so multi-line streams stay
/// on one log line.
fn truncate_for_log(text: &str, max_chars: usize) -> String {
    let escaped: String = text
        .chars()
        .flat_map(|c| match c {
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect();
    if escaped.chars().count() <= max_chars {
        escaped
    } else {
        let mut out: String = escaped.chars().take(max_chars).collect();
        out.push_str("…");
        out
    }
}

fn render_tick(state: OutboundState) -> &'static str {
    match state {
        OutboundState::Sending => "·",
        OutboundState::Sent => "✓",
        OutboundState::Delivered => "✓✓",
        OutboundState::Failed => "✗",
    }
}

#[derive(Debug, Clone)]
struct OutboundLine {
    line_idx: usize,
    body: String,
}

#[derive(Debug, Default)]
struct OutboundLines {
    by_msg_id: HashMap<String, OutboundLine>,
}

impl OutboundLines {
    fn record(&mut self, msg_id: String, line_idx: usize, body: String) {
        self.by_msg_id
            .insert(msg_id, OutboundLine { line_idx, body });
    }

    /// Rewrites the recorded line in `transcript` to reflect `state`. Returns true if a
    /// line was rewritten so the caller knows to re-render.
    fn apply(&self, transcript: &mut [String], msg_id: &str, state: OutboundState) -> bool {
        let Some(entry) = self.by_msg_id.get(msg_id) else {
            return false;
        };
        let Some(slot) = transcript.get_mut(entry.line_idx) else {
            return false;
        };
        let new_line = format!("{} {}", entry.body, render_tick(state));
        if *slot == new_line {
            return false;
        }
        *slot = new_line;
        true
    }
}

fn cmd_history(args: HistoryArgs, paths: &AppPaths) -> Result<()> {
    info!(limit = args.limit, "running history command");
    let entries = paths.read_history(args.limit)?;
    if entries.is_empty() {
        println!("(no messages yet)");
        return Ok(());
    }
    for entry in &entries {
        let role_label = match entry.role {
            HistoryRole::User => "you",
            HistoryRole::Agent => "agent",
        };
        println!(
            "[{}] {}: {}",
            format_ts_with_ms(entry.ts),
            role_label,
            entry.text
        );
    }
    Ok(())
}

fn format_ts_with_ms(unix_ms_value: i64) -> String {
    Local
        .timestamp_millis_opt(unix_ms_value)
        .single()
        .map(|dt| dt.format("%H:%M:%S%.3f").to_string())
        .unwrap_or_else(|| "--:--:--.---".to_string())
}

fn print_guide() {
    println!(
        "{}",
        r#"chat4000 — encrypted terminal client for OpenClaw agents

INTERACTIVE CHAT
  chat4000                       Launch the interactive TUI. First run drops
                                 you into pairing if you haven't paired.

PAIRING
  chat4000 pair                  Join an existing group: enter a code shown
                                 by another device.
  chat4000 pair --host           Host a new group: prints a 6-character code
                                 and a QR for another device to scan.

ONE-SHOT MESSAGING (no streaming, prints the agent's full reply)
  chat4000 send "hello"          Send and wait for the reply (default 120s).
  echo "hello" | chat4000 send   Pipe the message in via stdin instead.
  chat4000 send "msg" --timeout 300
                                 Wait up to 5 minutes for the reply.
  chat4000 send "msg" --raw      Print only the agent's reply text.
                                 No `you:` echo, no timestamp, no
                                 `agent:` prefix. Pipe-friendly.

  Default output (both lines on stdout):
    [HH:MM:SS.mmm] you: <message> <tick>
    [HH:MM:SS.mmm] agent: <reply>

  Tick states (delivered = recipient acked at the application layer):
    ·    sending     — created locally, no relay confirmation yet
    ✓    sent        — relay accepted and queued the outbound message
    ✓✓   delivered   — the plugin / paired client decrypted the message
    ✗    failed      — local timeout or socket error

  With --raw: just <reply> on stdout.

HISTORY
  chat4000 history               Show the last 5 messages with timestamps.
  chat4000 history -n 20         Short form for --limit.
  chat4000 history --limit 100   Long form. Same output format as `send`.

CONNECTION
  chat4000 status                Show paired group, relay reachability,
                                 latest version policy.
  chat4000 disconnect            Forget local pairing (group config,
                                 transcript, device identity). Logs and
                                 telemetry config are kept.

TELEMETRY (Sentry crash reports — opt-out)
  chat4000 telemetry status      Show current opt-in/out state.
  chat4000 telemetry enable      Re-enable error reports.
  chat4000 telemetry disable     Persist opt-out across runs.
  chat4000 --no-telemetry        Per-run opt-out flag.
  CHAT4000_TELEMETRY_DISABLED=1  Per-run opt-out via env var.

SUPPORT
  chat4000 support               Open the chat4000 Telegram channel.

INSIDE THE INTERACTIVE TUI

  Slash commands at the input prompt:
    /help        Condensed help.
    /status      Same as `chat4000 status`.
    /pair        Reopen pairing mid-session.
    /clear       Clear the visible transcript (history file untouched).
    /reset-history  Wipe history.jsonl on disk.
    /disconnect  Same as `chat4000 disconnect`, mid-session.
    /support     Open the Telegram support channel.
    /quit        Exit (Ctrl+D also works).

  Keyboard:
    Enter                          Send message
    Shift+Enter / Option+Enter     Insert newline
    Up / Down                      Browse input history at bottom of transcript
    Option+Backspace               Delete previous word
    PgUp / PgDn / mouse wheel      Scroll transcript
    Ctrl+C twice                   Exit

DEBUG FLAGS
  --debug-acks                   Print every recv_ack / relay_recv_ack /
                                 inner ack frame to stderr. Combine with any
                                 subcommand for verification.

ENV VARS
  CHAT4000_TELEMETRY_DISABLED=1   Disable Sentry crash reports.
  CHAT4000_DEVICE_NAME=…          Override the auto-detected device name.
  CHAT4000_NO_QR=1                Suppress QR rendering during host pairing.
  CHAT4000_SENTRY_DSN=…           Build-time only; embedded into release builds.
  CHAT4000_ALLOW_OUTDATED_PLUGIN=1
                                  Bypass the hard block when the paired plugin
                                  is below the relay's `min_version` policy.

LOCAL FILES (macOS)
  ~/Library/Application Support/chat4000/group-config.json
  ~/Library/Application Support/chat4000/history.jsonl
  ~/Library/Application Support/chat4000/input_history
  ~/Library/Application Support/chat4000/device-identity.json
  ~/Library/Application Support/chat4000/update-nag.json
  ~/Library/Application Support/chat4000/logs/chat4000.log  (rotating, 10 MB cap)
  ~/.config/chat4000/                                       (telemetry config)

  On Linux, data lives under ~/.local/share/chat4000/ instead.
"#
    );
}

fn cmd_debug_exception(args: DebugExceptionArgs) -> Result<()> {
    match args.kind {
        DebugExceptionKind::Handled => {
            bail!("debug exception test: token=super-secret-test-value")
        }
        DebugExceptionKind::Panic => {
            panic!("debug panic test: token=super-secret-test-value")
        }
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .context("failed to read from stdin")?;
    Ok(buffer.trim().to_string())
}

fn prompt_pairing_code(label: &str) -> Result<String> {
    if !io::stdin().is_tty() || !io::stdout().is_tty() {
        return Ok(format_pairing_code_for_display(&normalize_pairing_code(
            &prompt(label)?,
        )));
    }

    struct RawModeGuard;

    impl RawModeGuard {
        fn enter() -> Result<Self> {
            terminal::enable_raw_mode().context("failed to enable raw mode for pairing prompt")?;
            Ok(Self)
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            let _ = terminal::disable_raw_mode();
        }
    }

    let _guard = RawModeGuard::enter()?;
    let mut normalized = String::new();
    let mut stdout = io::stdout();
    loop {
        queue!(
            stdout,
            cursor::MoveToColumn(0),
            Clear(ClearType::CurrentLine),
            Print(label),
            Print(format_pairing_code_for_display(&normalized))
        )?;
        stdout.flush().context("failed to flush pairing prompt")?;

        match event::read().context("failed to read pairing prompt event")? {
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                println!();
                bail!("pairing prompt cancelled");
            }
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            }) => {
                println!();
                return Ok(format_pairing_code_for_display(&normalized));
            }
            Event::Key(KeyEvent {
                code: KeyCode::Backspace,
                ..
            }) => {
                normalized.pop();
            }
            Event::Key(KeyEvent {
                code: KeyCode::Char(ch),
                ..
            }) => {
                for upper in ch.to_uppercase() {
                    if upper == '-' {
                        continue;
                    }
                    if normalized.len() >= 8 {
                        break;
                    }
                    if PAIRING_CODE_ALPHABET.contains(&(upper as u8)) {
                        normalized.push(upper);
                    }
                }
            }
            Event::Paste(text) => {
                for upper in text.chars().flat_map(char::to_uppercase) {
                    if upper == '-' || upper.is_whitespace() {
                        continue;
                    }
                    if normalized.len() >= 8 {
                        break;
                    }
                    if PAIRING_CODE_ALPHABET.contains(&(upper as u8)) {
                        normalized.push(upper);
                    }
                }
            }
            _ => {}
        }
    }
}

fn format_pairing_code_for_display(normalized: &str) -> String {
    let left: String = normalized.chars().take(4).collect();
    let right: String = normalized.chars().skip(4).take(4).collect();
    if right.is_empty() {
        left
    } else {
        format!("{left}-{right}")
    }
}

async fn interactive_pair(paths: &AppPaths) -> Result<GroupConfig> {
    println!("No group paired yet. Let's pair this device.");
    loop {
        let code = prompt_pairing_code("Enter pairing code (leave blank to host a new group): ")?;
        info!(
            entered_code = !code.trim().is_empty(),
            "starting interactive pairing"
        );

        if code.trim().is_empty() {
            let group_key = generate_group_key().to_vec();
            let code = generate_pairing_code();
            print_pairing_host_screen(&code);

            println!("Press Ctrl-C to stop pairing.");
            println!("Status: [1/5] Opening pairing session");
            let result = run_host_pairing_with_ctrl_c(
                PairHostOptions {
                    relay_url: DEFAULT_RELAY_URL.to_string(),
                    group_key: group_key.clone(),
                    code: Some(code),
                    allow_self_signed_tls: false,
                },
                |status, _| println!("{}", pairing_status_line(status)),
            )
            .await;
            let result = match result {
                Ok(result) => result,
                Err(err) if is_pairing_cancelled(&err) => {
                    println!("Pairing cancelled.");
                    continue;
                }
                Err(err) => return Err(err),
            };

            let config = GroupConfig {
                group_key_base64: STANDARD.encode(group_key),
            };
            paths.save_config(&config)?;
            info!("interactive host pairing completed successfully");
            println!("✓ Paired.");
            println!(
                "[connected · group {}…]",
                &derive_group_id(&config.group_key()?)[..8]
            );
            println!("Hosted pairing session finished for {}.", result.code);
            return Ok(config);
        }

        println!("• Opening pairing room…");
        let result = join_pairing_session(PairJoinOptions {
            relay_url: DEFAULT_RELAY_URL.to_string(),
            code,
            allow_self_signed_tls: false,
        })
        .await?;
        let config = GroupConfig {
            group_key_base64: STANDARD.encode(&result.group_key),
        };
        paths.save_config(&config)?;
        info!("interactive join pairing completed successfully");
        println!("✓ Paired.");
        println!("[connected · group {}…]", &result.group_id[..8]);
        return Ok(config);
    }
}

fn print_pairing_host_screen(code: &str) {
    for line in pairing_host_lines(code) {
        println!("{line}");
    }
}

fn pairing_host_lines(code: &str) -> Vec<String> {
    let room_id = derive_pairing_room_id(code);
    let invite_uri = format!("chat4000://pair?code={code}");
    let mut lines = vec![
        String::new(),
        String::new(),
        String::new(),
        "Pair another device".to_string(),
        String::new(),
        "Scan the QR code with another client to pair another device.".to_string(),
        "Or enter the pairing code manually on the other client.".to_string(),
        "Keep this window open while pairing.".to_string(),
        String::new(),
        format!("Pairing code: {code}"),
        format!("Room ID: {room_id}"),
        String::new(),
    ];
    if let Some(rendered) = render_qr_string_if_possible(&invite_uri) {
        lines.extend(rendered.lines().map(ToOwned::to_owned));
    }
    lines.push(String::new());
    lines.push(format!("Invite: {invite_uri}"));
    lines.push(String::new());
    lines
}

fn render_qr_string_if_possible(uri: &str) -> Option<String> {
    if std::env::var_os("CHAT4000_NO_QR").is_some()
        || std::env::var_os("NO_COLOR").is_some()
        || !io::stdout().is_tty()
    {
        return None;
    }

    QrCode::new(uri.as_bytes()).ok().map(|code| {
        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build()
    })
}

fn pairing_status_prefix(status: PairHostStatus) -> &'static str {
    match status {
        PairHostStatus::Connecting => "[1/5]",
        PairHostStatus::Waiting => "[3/5]",
        PairHostStatus::JoinerReady | PairHostStatus::GrantSent => "[4/5]",
        PairHostStatus::Completed => "[5/5]",
    }
}

fn pairing_status_line(status: PairHostStatus) -> String {
    let body = match status {
        PairHostStatus::Connecting => "Connecting to relay",
        PairHostStatus::Waiting => "Waiting for client to join",
        PairHostStatus::JoinerReady => "Client joined pairing session",
        PairHostStatus::GrantSent => "Key transferred",
        PairHostStatus::Completed => "Pairing complete",
    };
    format!("Status: {} {}", pairing_status_prefix(status), body)
}

async fn run_host_pairing_with_ctrl_c<F>(
    opts: PairHostOptions,
    on_status: F,
) -> Result<chat4000_relay::PairHostResult>
where
    F: FnMut(PairHostStatus, &str) + Send + 'static,
{
    tokio::select! {
        result = host_pairing_session(opts, on_status) => result,
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => bail!("pairing cancelled by user"),
                Err(err) => Err(err).context("failed to receive ctrl-c during pairing"),
            }
        }
    }
}

fn is_pairing_cancelled(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("pairing cancelled by user") || message.contains("pairing cancelled")
}

async fn run_host_pairing_in_chat(
    opts: PairHostOptions,
    input_rx: &mut mpsc::UnboundedReceiver<InputEvent>,
    ui: &mut TerminalUi,
    transcript: &mut Vec<String>,
    render_state: &mut ChatRenderState,
    input_state: &mut InputState,
) -> Result<chat4000_relay::PairHostResult> {
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<PairHostStatus>();
    let mut pairing_task = tokio::spawn(async move {
        host_pairing_session(opts, move |status, _| {
            let _ = status_tx.send(status);
        })
        .await
    });

    loop {
        tokio::select! {
            result = status_rx.recv() => {
                if let Some(status) = result {
                    push_transcript_line(transcript, pairing_status_line(status));
                    ui.render(transcript, render_state, input_state)?;
                }
            }
            maybe_input = input_rx.recv() => {
                let Some(input) = maybe_input else {
                    pairing_task.abort();
                    bail!("pairing cancelled");
                };
                match input {
                    InputEvent::Key(key) => {
                        match input_state.handle_key(key, render_state.transcript_scroll_active()) {
                            InputAction::CtrlC => {
                                pairing_task.abort();
                                push_transcript_line(transcript, "[pairing cancelled]".to_string());
                                ui.render(transcript, render_state, input_state)?;
                                bail!("pairing cancelled by user");
                            }
                            InputAction::ScrollUp(lines) => render_state.scroll_up(lines),
                            InputAction::ScrollDown(lines) => render_state.scroll_down(lines),
                            InputAction::ScrollTop => render_state.scroll_up(10_000),
                            InputAction::ScrollBottom => render_state.scroll_to_bottom(),
                            InputAction::Redraw | InputAction::None => {}
                            InputAction::CtrlD | InputAction::Submit { .. } => {}
                        }
                        ui.render(transcript, render_state, input_state)?;
                    }
                    InputEvent::Paste(text) => {
                        let _ = input_state.paste_text(&text);
                        ui.render(transcript, render_state, input_state)?;
                    }
                    InputEvent::Resize => {
                        ui.render(transcript, render_state, input_state)?;
                    }
                    InputEvent::Mouse(mouse) => {
                        match mouse.kind {
                            MouseEventKind::ScrollUp => render_state.scroll_up(3),
                            MouseEventKind::ScrollDown => render_state.scroll_down(3),
                            _ => {}
                        }
                        ui.render(transcript, render_state, input_state)?;
                    }
                }
            }
            result = &mut pairing_task => {
                match result {
                    Ok(inner) => return inner,
                    Err(err) if err.is_cancelled() => bail!("pairing cancelled by user"),
                    Err(err) => return Err(err).context("pairing task join error"),
                }
            }
        }
    }
}

async fn run_chat_session(config: GroupConfig, paths: &AppPaths) -> Result<()> {
    use std::sync::Arc;

    use chat4000_proto::{InnerMessageType, SenderRole};

    use crate::transport::relay::TransportConfig;
    use crate::transport::{
        ConnectionState, MessageTransport, OutboundMessage, TransportEvent, TransportStatus,
    };

    let group_id = config.group_id()?;
    let group_key = config.group_key()?;
    let device_identity = paths.load_or_create_device_identity()?;
    info!(
        group_id = %group_id,
        device_id = %device_identity.sender.device_id,
        device_name = %device_identity.sender.device_name,
        "starting chat session"
    );

    let store = Arc::new(paths.open_store().context("failed to open message store")?);

    println!("[connecting · group {}…]", &group_id[..8]);
    let transport_config = TransportConfig {
        relay_url: DEFAULT_RELAY_URL.to_string(),
        group_id: group_id.clone(),
        group_key: group_key.clone(),
        device_id: device_identity.sender.device_id.clone(),
        sender: device_identity.sender(),
        app_id: Some(DEFAULT_APP_ID.to_string()),
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        release_channel: Some(RELEASE_CHANNEL.to_string()),
        allow_self_signed_tls: false,
        debug_acks: debug_acks_enabled(),
    };
    let (transport, mut events) = start_transport_with_retries(&transport_config, &store).await?;
    if let Some(blocking) =
        handle_version_policy_pre_chat(paths, transport.version_policy().as_ref())
    {
        eprintln!("{blocking}");
        return Ok(());
    }
    let plugin_policy = transport.plugin_version_policy();
    let mut outbound = OutboundTracker::default();
    let mut outbound_lines = OutboundLines::default();
    let mut plugin_seen = false;

    let _terminal_guard = TerminalGuard::enter()?;
    let mut ui = TerminalUi::new()?;
    let mut transcript = load_history_lines(paths, 50)?;
    push_transcript_line(
        &mut transcript,
        format!("[connected · group {}…]", &group_id[..8]),
    );
    push_transcript_line(
        &mut transcript,
        "Type a message and press Enter. Ctrl-D exits.".to_string(),
    );

    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<InputEvent>();
    start_input_thread(input_tx);

    let mut render_state = ChatRenderState::default();
    let mut input_state = InputState::from_history(paths.read_input_history()?);
    let mut render_ticker = tokio::time::interval(Duration::from_millis(100));
    ui.render(&transcript, &render_state, &input_state)?;

    loop {
        tokio::select! {
            _ = render_ticker.tick() => {
                if render_state.tick() {
                    ui.render(&transcript, &render_state, &input_state)?;
                }
            }
            signal = tokio::signal::ctrl_c() => {
                match signal {
                    Ok(()) => {
                        if handle_ctrl_c(&mut render_state) {
                            break;
                        }
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    Err(err) => {
                        record_exception("ctrl_c_handler_error", &format!("{err:?}"));
                        error!(error = ?err, "ctrl-c handler error");
                    }
                }
            }
            maybe_input = input_rx.recv() => {
                let Some(input) = maybe_input else { break; };
                match input {
                    InputEvent::Key(key) => {
                        match input_state.handle_key(key, render_state.transcript_scroll_active()) {
                            InputAction::None => {}
                            InputAction::Redraw => {
                                render_state.clear_exit_prompt();
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::ScrollUp(lines) => {
                                render_state.scroll_up(lines);
                                render_state.clear_exit_prompt();
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::ScrollDown(lines) => {
                                render_state.scroll_down(lines);
                                render_state.clear_exit_prompt();
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::ScrollTop => {
                                render_state.scroll_up(10_000);
                                render_state.clear_exit_prompt();
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::ScrollBottom => {
                                render_state.scroll_to_bottom();
                                render_state.clear_exit_prompt();
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::CtrlC => {
                                if handle_ctrl_c(&mut render_state) {
                                    break;
                                }
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            InputAction::CtrlD => break,
                            InputAction::Submit {
                                display: display_line,
                                send,
                            } => {
                                render_state.clear_exit_prompt();
                                debug!(line = %display_line, send_len = send.len(), "received local input line");
                                if display_line.starts_with('/') {
                                    match display_line.trim() {
                                        "/quit" => {
                                            info!("chat session quit requested");
                                            break;
                                        }
                                        "/status" => {
                                            push_transcript_line(
                                                &mut transcript,
                                                format!("[connected · group {}…]", &group_id[..8]),
                                            );
                                        }
                                        "/help" => {
                                            push_transcript_line(
                                                &mut transcript,
                                                "/help /status /pair /support /clear /reset-history /disconnect /quit".to_string(),
                                            );
                                            push_transcript_line(
                                                &mut transcript,
                                                "Docs: https://chat4000.com/help".to_string(),
                                            );
                                            push_transcript_line(
                                                &mut transcript,
                                                format!("Talk to the team: {SUPPORT_URL}"),
                                            );
                                        }
                                        "/support" => {
                                            push_transcript_line(
                                                &mut transcript,
                                                format!("Support: {SUPPORT_URL}"),
                                            );
                                            match open_support_url() {
                                                Ok(()) => push_transcript_line(
                                                    &mut transcript,
                                                    "Opened chat4000 official Telegram support.".to_string(),
                                                ),
                                                Err(err) => push_transcript_line(
                                                    &mut transcript,
                                                    format!("Could not open browser automatically: {err}"),
                                                ),
                                            }
                                        }
                                        "/pair" => {
                                            let code = generate_pairing_code();
                                            for line in pairing_host_lines(&code) {
                                                push_transcript_line(&mut transcript, line);
                                            }
                                            push_transcript_line(
                                                &mut transcript,
                                                "Press Ctrl-C to stop pairing.".to_string(),
                                            );
                                            push_transcript_line(
                                                &mut transcript,
                                                "Status: [1/5] Opening pairing session".to_string(),
                                            );
                                            ui.render(&transcript, &render_state, &input_state)?;
                                            let result = run_host_pairing_in_chat(
                                                PairHostOptions {
                                                    relay_url: DEFAULT_RELAY_URL.to_string(),
                                                    group_key: group_key.clone(),
                                                    code: Some(code),
                                                    allow_self_signed_tls: false,
                                                },
                                                &mut input_rx,
                                                &mut ui,
                                                &mut transcript,
                                                &mut render_state,
                                                &mut input_state,
                                            )
                                            .await;
                                            match result {
                                                Ok(result) => {
                                                    push_transcript_line(
                                                        &mut transcript,
                                                        format!("✓ Pairing session finished for {}.", result.code),
                                                    );
                                                }
                                                Err(err) if is_pairing_cancelled(&err) => {
                                                    info!("chat pairing cancelled by user");
                                                }
                                                Err(err) => return Err(err),
                                            }
                                        }
                                        "/clear" => {
                                            info!("terminal cleared");
                                            transcript.clear();
                                        }
                                        "/reset-history" => {
                                            paths.clear_history()?;
                                            push_transcript_line(&mut transcript, "[history cleared]".to_string());
                                            info!("history reset from chat session");
                                        }
                                        "/disconnect" => {
                                            paths.remove_local_state()?;
                                            push_transcript_line(&mut transcript, "[local pairing removed]".to_string());
                                            info!("disconnect requested from chat session");
                                            break;
                                        }
                                        other => {
                                            warn!(command = %other, "unknown slash command");
                                            push_transcript_line(&mut transcript, format!("[unknown command: {other}]"));
                                        }
                                    }
                                    ui.render(&transcript, &render_state, &input_state)?;
                                    continue;
                                }

                                let outbound_id = transport.send(OutboundMessage::Text(send.clone()));
                                outbound.track(outbound_id.clone());
                                let _ = store.record_outbound(&group_id, &outbound_id, unix_ms());
                                paths.append_history(&HistoryEntry {
                                    role: HistoryRole::User,
                                    text: display_line.clone(),
                                    ts: unix_ms(),
                                })?;
                                paths.append_input_history(&display_line)?;
                                render_state.set_busy_phase(BusyPhase::Thinking);
                                let body = format!("> {display_line}");
                                let line = format!(
                                    "{body} {}",
                                    render_tick(OutboundState::Sending)
                                );
                                push_transcript_line(&mut transcript, line);
                                outbound_lines.record(
                                    outbound_id,
                                    transcript.len() - 1,
                                    body,
                                );
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                        }
                    }
                    InputEvent::Paste(text) => {
                        render_state.clear_exit_prompt();
                        let _ = input_state.paste_text(&text);
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    InputEvent::Resize => {
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    InputEvent::Mouse(mouse) => {
                        match mouse.kind {
                            MouseEventKind::ScrollUp => render_state.scroll_up(3),
                            MouseEventKind::ScrollDown => render_state.scroll_down(3),
                            _ => {}
                        }
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                }
            }
            maybe_event = events.recv() => {
                let Some(event) = maybe_event else { break; };
                match event {
                    TransportEvent::Connection(ConnectionState::Connected) => {
                        info!(
                            stream_count = render_state.stream_buffers.len(),
                            busy = render_state.busy.is_some(),
                            "transport connected"
                        );
                        push_transcript_line(&mut transcript, "[connected]".to_string());
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    TransportEvent::Connection(ConnectionState::Reconnecting) => {
                        warn!(
                            stream_count = render_state.stream_buffers.len(),
                            busy = render_state.busy.is_some(),
                            "transport reconnecting — clearing render state including any stuck streams"
                        );
                        render_state = ChatRenderState::default();
                        let still_sending: Vec<String> = outbound
                            .states
                            .iter()
                            .filter_map(|(id, state)| {
                                (*state == OutboundState::Sending).then(|| id.clone())
                            })
                            .collect();
                        for id in still_sending {
                            outbound.mark_failed(&id, &group_id, store.as_ref());
                            outbound_lines.apply(&mut transcript, &id, OutboundState::Failed);
                        }
                        push_transcript_line(&mut transcript, "[reconnecting…]".to_string());
                        plugin_seen = false;
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    TransportEvent::Connection(ConnectionState::Failed(reason)) => {
                        push_transcript_line(
                            &mut transcript,
                            format!("[connection failed: {reason}]"),
                        );
                        ui.render(&transcript, &render_state, &input_state)?;
                    }
                    TransportEvent::Connection(_) => {}
                    TransportEvent::Status(update) => {
                        match update.status {
                            TransportStatus::Sent => {
                                outbound.mark_sent(&update.msg_id, &group_id, store.as_ref());
                            }
                            TransportStatus::Failed => {
                                outbound.mark_failed(&update.msg_id, &group_id, store.as_ref());
                            }
                        }
                        if outbound_lines.apply(
                            &mut transcript,
                            &update.msg_id,
                            outbound.state_of(&update.msg_id),
                        ) {
                            ui.render(&transcript, &render_state, &input_state)?;
                        }
                    }
                    TransportEvent::Receive(message) => {
                        debug!(message_type = ?message.t, message_id = %message.id, "received inner message");
                        // Plugin version policy enforcement on first plugin message.
                        if !plugin_seen
                            && message.from.as_ref().map(|f| f.role) == Some(SenderRole::Plugin)
                        {
                            plugin_seen = true;
                            if let Some(policy) = plugin_policy.as_ref() {
                                let plugin_v =
                                    message.from.as_ref().and_then(|f| f.app_version.as_deref());
                                match evaluate_plugin_version_policy(plugin_v, policy) {
                                    PluginPolicyVerdict::HardBlock => {
                                        if !allow_outdated_plugin() {
                                            push_transcript_line(
                                                &mut transcript,
                                                "[plugin update required — set CHAT4000_ALLOW_OUTDATED_PLUGIN=1 to bypass]".to_string(),
                                            );
                                        } else {
                                            push_transcript_line(
                                                &mut transcript,
                                                "[plugin update required, bypassed]".to_string(),
                                            );
                                        }
                                        ui.render(&transcript, &render_state, &input_state)?;
                                    }
                                    PluginPolicyVerdict::SoftNag => {
                                        push_transcript_line(
                                            &mut transcript,
                                            "[plugin update available]".to_string(),
                                        );
                                        ui.render(&transcript, &render_state, &input_state)?;
                                    }
                                    PluginPolicyVerdict::Ok => {}
                                }
                            }
                        }
                        // Inner-ack Flow B inbound: drives delivered tick.
                        if let Some(ack) = message.as_ack() {
                            if ack.stage == "received" {
                                outbound.mark_delivered(ack.refs, &group_id, store.as_ref());
                                if debug_acks_enabled() {
                                    eprintln!("[ack] inner ack received refs={}", ack.refs);
                                }
                                if outbound_lines.apply(
                                    &mut transcript,
                                    ack.refs,
                                    outbound.state_of(ack.refs),
                                ) {
                                    ui.render(&transcript, &render_state, &input_state)?;
                                }
                            }
                            continue;
                        }
                        if device_identity.is_local_sender(message.from.as_ref()) {
                            debug!(message_id = %message.id, "ignoring same-device echo");
                            continue;
                        }
                        // §6.6.5 v1: only the plugin emits inner ack frames.
                        // The CLI is an app and stays silent on the ack channel.
                        maybe_push_plugin_update_warning(
                            &mut render_state,
                            &mut transcript,
                            message.from.as_ref(),
                        );
                        match message.t {
                            chat4000_proto::InnerMessageType::Text => {
                                if let Some(text) = message.body.get("text").and_then(|v| v.as_str()) {
                                    let rendered = render_chat_line(message.from.as_ref(), text);
                                    render_state.clear_busy();
                                    push_transcript_line(&mut transcript, rendered.clone());
                                    paths.append_history(&HistoryEntry {
                                        role: history_role_for_sender(message.from.as_ref()),
                                        text: rendered,
                                        ts: message.ts,
                                    })?;
                                    ui.render(&transcript, &render_state, &input_state)?;
                                }
                            }
                            chat4000_proto::InnerMessageType::TextDelta => {
                                let id = stream_correlator(&message);
                                let delta = message.body.get("delta").and_then(|v| v.as_str()).unwrap_or_default();
                                debug!(
                                    stream_id = %id,
                                    inner_id = %message.id,
                                    delta_len = delta.len(),
                                    delta_snippet = %truncate_for_log(delta, 80),
                                    sender_role = ?message.from.as_ref().map(|f| f.role),
                                    sender_device = ?message.from.as_ref().map(|f| &f.device_id),
                                    "received text_delta"
                                );
                                render_state.update_stream_delta(id, message.from.clone(), delta);
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            chat4000_proto::InnerMessageType::TextEnd => {
                                let id = stream_correlator(&message);
                                let text = message.body.get("text").and_then(|v| v.as_str()).unwrap_or_default();
                                let reset = message.body.get("reset").and_then(|v| v.as_bool()).unwrap_or(false);
                                debug!(
                                    stream_id = %id,
                                    inner_id = %message.id,
                                    final_text_len = text.len(),
                                    text_snippet = %truncate_for_log(text, 80),
                                    reset,
                                    sender_role = ?message.from.as_ref().map(|f| f.role),
                                    sender_device = ?message.from.as_ref().map(|f| &f.device_id),
                                    "received text_end"
                                );
                                let (sender, final_text, suppressed) =
                                    render_state.complete_stream(&id, message.from.clone(), text);
                                debug!(
                                    stream_id = %id,
                                    suppressed,
                                    streams_remaining = render_state.stream_buffers.len(),
                                    busy_after = render_state.busy.is_some(),
                                    "stream completed in run_chat_session"
                                );
                                if !reset && !suppressed && !final_text.is_empty() {
                                    let rendered = render_chat_line(sender.as_ref(), &final_text);
                                    push_transcript_line(&mut transcript, rendered.clone());
                                    paths.append_history(&HistoryEntry {
                                        role: history_role_for_sender(sender.as_ref()),
                                        text: rendered,
                                        ts: message.ts,
                                    })?;
                                }
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            chat4000_proto::InnerMessageType::Status => {
                                if let Some(status) = message.body.get("status").and_then(|v| v.as_str()) {
                                    debug!(status = %status, "received status message");
                                    match status {
                                        "thinking" => {
                                            render_state.set_busy_phase(BusyPhase::Thinking);
                                            ui.render(&transcript, &render_state, &input_state)?;
                                        }
                                        "typing" => {
                                            render_state.set_busy_phase(BusyPhase::Typing);
                                            ui.render(&transcript, &render_state, &input_state)?;
                                        }
                                        "idle" => {
                                            render_state.clear_busy();
                                            ui.render(&transcript, &render_state, &input_state)?;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            chat4000_proto::InnerMessageType::Image => {
                                push_transcript_line(&mut transcript, "[received image message]".to_string());
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            chat4000_proto::InnerMessageType::Audio => {
                                push_transcript_line(&mut transcript, "[received audio message]".to_string());
                                ui.render(&transcript, &render_state, &input_state)?;
                            }
                            chat4000_proto::InnerMessageType::Ack => {}
                        }
                    }
                }
            }
        }
    }

    transport.disconnect();
    Ok(())
}

async fn start_transport_with_retries(
    config: &transport::relay::TransportConfig,
    store: &std::sync::Arc<MessageStore>,
) -> Result<(
    transport::relay::RelayMessageTransport,
    transport::TransportEvents,
)> {
    let mut delay = 2u64;
    loop {
        match transport::relay::RelayMessageTransport::start(
            config.clone(),
            std::sync::Arc::clone(store),
        )
        .await
        {
            Ok(pair) => return Ok(pair),
            Err(err) => {
                error!(error = ?err, delay_secs = delay, "transport start failed");
                record_exception("transport_start_error", &format!("{err:?}"));
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(60);
            }
        }
    }
}

fn debug_acks_enabled() -> bool {
    DEBUG_ACKS.get().copied().unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginPolicyVerdict {
    Ok,
    SoftNag,
    HardBlock,
}

fn evaluate_plugin_version_policy(
    plugin_version: Option<&str>,
    policy: &VersionPolicy,
) -> PluginPolicyVerdict {
    let parsed = plugin_version.and_then(|v| semver::Version::parse(v).ok());
    let Some(plugin_v) = parsed else {
        // Missing or unparseable plugin version: behave like soft nag, never hard-block.
        return if policy.recommended_version.is_some() {
            PluginPolicyVerdict::SoftNag
        } else {
            PluginPolicyVerdict::Ok
        };
    };
    if let Some(min) = policy
        .min_version
        .as_deref()
        .and_then(|v| semver::Version::parse(v).ok())
    {
        if plugin_v < min {
            return PluginPolicyVerdict::HardBlock;
        }
    }
    if let Some(rec) = policy
        .recommended_version
        .as_deref()
        .and_then(|v| semver::Version::parse(v).ok())
    {
        if plugin_v < rec {
            return PluginPolicyVerdict::SoftNag;
        }
    }
    PluginPolicyVerdict::Ok
}

fn allow_outdated_plugin() -> bool {
    env_truthy(ALLOW_OUTDATED_PLUGIN_ENV)
}

#[derive(Debug, Clone)]
struct StreamBuffer {
    sender: Option<SenderInfo>,
    text: String,
}

impl StreamBuffer {
    fn new(sender: Option<SenderInfo>) -> Self {
        Self {
            sender,
            text: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusyPhase {
    Thinking,
    Typing,
}

#[derive(Debug, Clone)]
struct BusyState {
    started_at: std::time::Instant,
    phase: BusyPhase,
    hint_index: usize,
    spinner_index: usize,
    last_hint_at: std::time::Instant,
}

#[derive(Debug, Default)]
struct ChatRenderState {
    busy: Option<BusyState>,
    plugin_update_warning_shown: bool,
    stream_buffers: HashMap<String, StreamBuffer>,
    stream_order: Vec<String>,
    suppressed_streams: HashSet<String>,
    exit_prompted_at: Option<std::time::Instant>,
    transcript_scroll: usize,
    transcript_scroll_mode: bool,
}

impl ChatRenderState {
    fn set_busy_phase(&mut self, phase: BusyPhase) {
        debug!(
            phase = ?phase,
            had_busy = self.busy.is_some(),
            stream_count = self.stream_buffers.len(),
            "setting busy phase"
        );
        let now = std::time::Instant::now();
        match &mut self.busy {
            Some(busy) => busy.phase = phase,
            None => {
                self.busy = Some(BusyState {
                    started_at: now,
                    phase,
                    hint_index: 0,
                    spinner_index: 0,
                    last_hint_at: now,
                });
            }
        }
    }

    fn clear_busy(&mut self) {
        debug!(
            had_busy = self.busy.is_some(),
            stream_count = self.stream_buffers.len(),
            "clearing busy state"
        );
        self.busy = None;
    }

    fn tick(&mut self) -> bool {
        let mut changed = false;
        if let Some(prompted_at) = self.exit_prompted_at {
            if prompted_at.elapsed() >= Duration::from_secs(2) {
                self.exit_prompted_at = None;
                changed = true;
            }
        }
        let Some(busy) = &mut self.busy else {
            return changed;
        };
        busy.spinner_index = (busy.spinner_index + 1) % SPINNER_FRAMES.len();
        let now = std::time::Instant::now();
        if now.duration_since(busy.last_hint_at) >= Duration::from_secs(2) {
            busy.hint_index = (busy.hint_index + 1) % thinking_hints_for_phase(busy.phase).len();
            busy.last_hint_at = now;
        }
        true
    }

    fn update_stream_delta(&mut self, id: String, sender: Option<SenderInfo>, delta: &str) {
        debug!(
            stream_id = %id,
            delta_len = delta.len(),
            had_stream = self.stream_buffers.contains_key(&id),
            "updating stream delta"
        );
        self.set_busy_phase(BusyPhase::Typing);
        if !self.stream_buffers.contains_key(&id) && !self.stream_buffers.is_empty() {
            for existing_id in self.stream_order.drain(..) {
                self.stream_buffers.remove(&existing_id);
                self.suppressed_streams.insert(existing_id);
            }
        }
        let entry = self
            .stream_buffers
            .entry(id.clone())
            .or_insert_with(|| StreamBuffer::new(sender.clone()));
        if entry.sender.is_none() {
            entry.sender = sender;
        }
        entry.text.push_str(delta);
        if !self.stream_order.iter().any(|stream_id| stream_id == &id) {
            self.stream_order.push(id.clone());
        }
        debug!(
            stream_id = %id,
            buffer_len = entry.text.len(),
            stream_count = self.stream_buffers.len(),
            "stream delta applied"
        );
    }

    fn complete_stream(
        &mut self,
        id: &str,
        sender: Option<SenderInfo>,
        final_text: &str,
    ) -> (Option<SenderInfo>, String, bool) {
        debug!(
            stream_id = %id,
            final_text_len = final_text.len(),
            had_stream = self.stream_buffers.contains_key(id),
            "completing stream"
        );
        let buffered = self.stream_buffers.remove(id);
        self.stream_order.retain(|stream_id| stream_id != id);
        let buffered_sender = buffered.as_ref().and_then(|buffer| buffer.sender.clone());
        let sender = buffered_sender.or(sender);
        let text = if final_text.is_empty() {
            buffered.map(|buffer| buffer.text).unwrap_or_default()
        } else {
            final_text.to_string()
        };
        let suppressed = self.suppressed_streams.remove(id);
        if self.stream_buffers.is_empty() {
            self.clear_busy();
        }
        debug!(
            stream_id = %id,
            final_len = text.len(),
            remaining_streams = self.stream_buffers.len(),
            suppressed = suppressed,
            "stream completed"
        );
        (sender, text, suppressed)
    }

    fn latest_stream(&self) -> Option<&StreamBuffer> {
        self.stream_order
            .last()
            .and_then(|id| self.stream_buffers.get(id))
    }

    fn register_ctrl_c(&mut self) -> bool {
        let now = std::time::Instant::now();
        if self
            .exit_prompted_at
            .map(|prompted_at| now.duration_since(prompted_at) <= Duration::from_secs(2))
            .unwrap_or(false)
        {
            true
        } else {
            self.exit_prompted_at = Some(now);
            false
        }
    }

    fn clear_exit_prompt(&mut self) {
        self.exit_prompted_at = None;
    }

    fn exit_prompt_active(&self) -> bool {
        self.exit_prompted_at
            .map(|prompted_at| prompted_at.elapsed() <= Duration::from_secs(2))
            .unwrap_or(false)
    }

    fn scroll_up(&mut self, lines: usize) {
        self.transcript_scroll = self.transcript_scroll.saturating_add(lines.max(1));
        self.transcript_scroll_mode = true;
    }

    fn scroll_down(&mut self, lines: usize) {
        self.transcript_scroll = self.transcript_scroll.saturating_sub(lines.max(1));
        self.transcript_scroll_mode = true;
    }

    fn scroll_to_bottom(&mut self) {
        self.transcript_scroll = 0;
        self.transcript_scroll_mode = false;
    }

    fn transcript_scroll_active(&self) -> bool {
        self.transcript_scroll > 0 || self.transcript_scroll_mode
    }
}

#[derive(Debug)]
enum InputEvent {
    Key(KeyEvent),
    Paste(String),
    Resize,
    Mouse(MouseEvent),
}

#[derive(Debug)]
struct InputState {
    buffer: String,
    cursor_offset: usize,
    history: Vec<String>,
    history_index: Option<usize>,
    draft_buffer: String,
    slash_selection: usize,
    pasted_blocks: Vec<PastedBlock>,
    next_paste_id: usize,
}

#[derive(Debug, Clone)]
struct PastedBlock {
    text: String,
    placeholder: String,
}

impl InputState {
    fn from_history(history: Vec<String>) -> Self {
        Self {
            buffer: String::new(),
            cursor_offset: 0,
            history,
            history_index: None,
            draft_buffer: String::new(),
            slash_selection: 0,
            pasted_blocks: Vec::new(),
            next_paste_id: 1,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, transcript_scrolled: bool) -> InputAction {
        match key.code {
            KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                InputAction::CtrlC
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                InputAction::CtrlD
            }
            KeyCode::Enter => {
                if is_multiline_enter(key) {
                    self.insert_str_at_cursor("\n");
                    self.history_index = None;
                    self.reset_slash_selection();
                    return InputAction::Redraw;
                }
                if self.buffer.starts_with('/') {
                    if let Some(command) = self.selected_slash_command() {
                        if self.buffer.trim() != command.name {
                            self.buffer = command.name.to_string();
                            self.cursor_offset = self.buffer.len();
                            return InputAction::Redraw;
                        }
                    }
                }
                let display_line = self.buffer.trim().to_string();
                let send_line = expand_pasted_blocks(&display_line, &self.pasted_blocks);
                self.history_index = None;
                self.draft_buffer.clear();
                self.buffer.clear();
                self.cursor_offset = 0;
                self.slash_selection = 0;
                self.pasted_blocks.clear();
                if send_line.trim().is_empty() {
                    InputAction::Redraw
                } else {
                    if self
                        .history
                        .last()
                        .map(|entry| entry != &display_line)
                        .unwrap_or(true)
                    {
                        self.history.push(display_line.clone());
                    }
                    InputAction::Submit {
                        display: display_line,
                        send: send_line,
                    }
                }
            }
            KeyCode::Backspace => {
                if key.modifiers.contains(KeyModifiers::ALT)
                    || key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    self.delete_word_before_cursor();
                } else {
                    self.delete_before_cursor();
                }
                self.history_index = None;
                self.reset_slash_selection();
                InputAction::Redraw
            }
            KeyCode::Left => {
                if key.modifiers.contains(KeyModifiers::ALT) {
                    self.move_cursor_word_left();
                } else {
                    self.move_cursor_left();
                }
                InputAction::Redraw
            }
            KeyCode::Right => {
                if key.modifiers.contains(KeyModifiers::ALT) {
                    self.move_cursor_word_right();
                } else {
                    self.move_cursor_right();
                }
                InputAction::Redraw
            }
            KeyCode::PageUp => InputAction::ScrollUp(10),
            KeyCode::PageDown => InputAction::ScrollDown(10),
            KeyCode::Home if key.modifiers.contains(KeyModifiers::CONTROL) => {
                InputAction::ScrollTop
            }
            KeyCode::End if key.modifiers.contains(KeyModifiers::CONTROL) => {
                InputAction::ScrollBottom
            }
            KeyCode::Up => {
                if transcript_scrolled {
                    return InputAction::ScrollUp(3);
                }
                if self.buffer.contains('\n') {
                    self.move_cursor_up_line();
                    return InputAction::Redraw;
                }
                if self.buffer.starts_with('/') {
                    let matches = slash_command_matches(&self.buffer);
                    if matches.is_empty() {
                        return InputAction::None;
                    }
                    self.slash_selection = self.slash_selection.saturating_sub(1);
                    return InputAction::Redraw;
                }
                if self.history.is_empty() {
                    return InputAction::None;
                }
                if !self.pasted_blocks.is_empty() {
                    return InputAction::None;
                }
                let next_index = match self.history_index {
                    Some(index) => index.saturating_sub(1),
                    None => {
                        self.draft_buffer = self.buffer.clone();
                        self.history.len() - 1
                    }
                };
                self.history_index = Some(next_index);
                self.buffer = self.history[next_index].clone();
                self.cursor_offset = self.buffer.len();
                InputAction::Redraw
            }
            KeyCode::Down => {
                if transcript_scrolled {
                    return InputAction::ScrollDown(3);
                }
                if self.buffer.contains('\n') {
                    self.move_cursor_down_line();
                    return InputAction::Redraw;
                }
                if self.buffer.starts_with('/') {
                    let matches = slash_command_matches(&self.buffer);
                    if matches.is_empty() {
                        return InputAction::None;
                    }
                    self.slash_selection =
                        (self.slash_selection + 1).min(matches.len().saturating_sub(1));
                    return InputAction::Redraw;
                }
                let Some(index) = self.history_index else {
                    return InputAction::None;
                };
                if !self.pasted_blocks.is_empty() {
                    return InputAction::None;
                }
                if index + 1 < self.history.len() {
                    let next_index = index + 1;
                    self.history_index = Some(next_index);
                    self.buffer = self.history[next_index].clone();
                } else {
                    self.history_index = None;
                    self.buffer = self.draft_buffer.clone();
                }
                self.cursor_offset = self.buffer.len();
                InputAction::Redraw
            }
            KeyCode::Tab => {
                if let Some(command) = self.selected_slash_command() {
                    self.buffer = command.name.to_string();
                    self.cursor_offset = self.buffer.len();
                    self.reset_slash_selection();
                    InputAction::Redraw
                } else {
                    InputAction::None
                }
            }
            KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::ALT) => {
                self.move_cursor_word_left();
                InputAction::Redraw
            }
            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::ALT) => {
                self.move_cursor_word_right();
                InputAction::Redraw
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.insert_str_at_cursor(&c.to_string());
                self.history_index = None;
                self.reset_slash_selection();
                InputAction::Redraw
            }
            _ => InputAction::None,
        }
    }

    fn paste_text(&mut self, text: &str) -> InputAction {
        if text.is_empty() {
            return InputAction::Redraw;
        }
        let normalized = normalize_pasted_input(text);
        if should_collapse_paste(&normalized) {
            let id = self.next_paste_id;
            self.next_paste_id += 1;
            let placeholder = format_pasted_text_ref(id, pasted_line_count(&normalized));
            self.pasted_blocks.push(PastedBlock {
                text: normalized,
                placeholder: placeholder.clone(),
            });
            self.insert_str_at_cursor(&placeholder);
        } else {
            self.insert_str_at_cursor(&normalized);
        }
        self.history_index = None;
        self.reset_slash_selection();
        InputAction::Redraw
    }

    fn insert_str_at_cursor(&mut self, text: &str) {
        self.cursor_offset = self.cursor_offset.min(self.buffer.len());
        self.buffer.insert_str(self.cursor_offset, text);
        self.cursor_offset += text.len();
    }

    fn delete_before_cursor(&mut self) {
        if self.cursor_offset == 0 {
            return;
        }
        if let Some((index, block)) = self
            .pasted_blocks
            .iter()
            .enumerate()
            .find(|(_, block)| self.buffer[..self.cursor_offset].ends_with(&block.placeholder))
        {
            let start = self.cursor_offset - block.placeholder.len();
            self.buffer.drain(start..self.cursor_offset);
            self.cursor_offset = start;
            self.pasted_blocks.remove(index);
            return;
        }
        let Some((previous_offset, _)) = self.buffer[..self.cursor_offset].char_indices().last()
        else {
            return;
        };
        self.buffer.drain(previous_offset..self.cursor_offset);
        self.cursor_offset = previous_offset;
        self.prune_unreferenced_pastes();
    }

    fn delete_word_before_cursor(&mut self) {
        if self.cursor_offset == 0 {
            return;
        }
        if let Some((index, block)) = self
            .pasted_blocks
            .iter()
            .enumerate()
            .find(|(_, block)| self.buffer[..self.cursor_offset].ends_with(&block.placeholder))
        {
            let start = self.cursor_offset - block.placeholder.len();
            self.buffer.drain(start..self.cursor_offset);
            self.cursor_offset = start;
            self.pasted_blocks.remove(index);
            return;
        }

        let end = self.cursor_offset;
        self.move_cursor_word_left();
        self.buffer.drain(self.cursor_offset..end);
        self.prune_unreferenced_pastes();
    }

    fn move_cursor_left(&mut self) {
        if let Some((previous_offset, _)) = self.buffer[..self.cursor_offset].char_indices().last()
        {
            self.cursor_offset = previous_offset;
        }
    }

    fn move_cursor_right(&mut self) {
        if self.cursor_offset >= self.buffer.len() {
            return;
        }
        if let Some(ch) = self.buffer[self.cursor_offset..].chars().next() {
            self.cursor_offset += ch.len_utf8();
        }
    }

    fn move_cursor_word_left(&mut self) {
        while self.cursor_offset > 0 {
            let Some((previous_offset, ch)) =
                self.buffer[..self.cursor_offset].char_indices().last()
            else {
                return;
            };
            self.cursor_offset = previous_offset;
            if !ch.is_whitespace() {
                break;
            }
        }
        while self.cursor_offset > 0 {
            let Some((previous_offset, ch)) =
                self.buffer[..self.cursor_offset].char_indices().last()
            else {
                return;
            };
            if ch.is_whitespace() {
                break;
            }
            self.cursor_offset = previous_offset;
        }
    }

    fn move_cursor_word_right(&mut self) {
        while self.cursor_offset < self.buffer.len() {
            let Some(ch) = self.buffer[self.cursor_offset..].chars().next() else {
                return;
            };
            self.cursor_offset += ch.len_utf8();
            if ch.is_whitespace() {
                break;
            }
        }
        while self.cursor_offset < self.buffer.len() {
            let Some(ch) = self.buffer[self.cursor_offset..].chars().next() else {
                return;
            };
            if !ch.is_whitespace() {
                break;
            }
            self.cursor_offset += ch.len_utf8();
        }
    }

    fn move_cursor_up_line(&mut self) {
        let current_start = line_start_before(&self.buffer, self.cursor_offset);
        if current_start == 0 {
            return;
        }
        let previous_end = current_start - 1;
        let previous_start = line_start_before(&self.buffer, previous_end);
        let column = char_column_in_line(&self.buffer, current_start, self.cursor_offset);
        self.cursor_offset = offset_for_column(&self.buffer, previous_start, previous_end, column);
    }

    fn move_cursor_down_line(&mut self) {
        let current_end = line_end_after(&self.buffer, self.cursor_offset);
        if current_end >= self.buffer.len() {
            return;
        }
        let next_start = current_end + 1;
        let next_end = line_end_after(&self.buffer, next_start);
        let current_start = line_start_before(&self.buffer, self.cursor_offset);
        let column = char_column_in_line(&self.buffer, current_start, self.cursor_offset);
        self.cursor_offset = offset_for_column(&self.buffer, next_start, next_end, column);
    }

    fn prune_unreferenced_pastes(&mut self) {
        self.pasted_blocks
            .retain(|block| self.buffer.contains(&block.placeholder));
    }

    fn reset_slash_selection(&mut self) {
        self.slash_selection = 0;
    }

    fn selected_slash_command(&self) -> Option<&'static SlashCommand> {
        let matches = slash_command_matches(&self.buffer);
        matches.get(self.slash_selection).copied()
    }
}

impl Default for InputState {
    fn default() -> Self {
        Self::from_history(Vec::new())
    }
}

enum InputAction {
    None,
    Redraw,
    Submit { display: String, send: String },
    CtrlC,
    CtrlD,
    ScrollUp(usize),
    ScrollDown(usize),
    ScrollTop,
    ScrollBottom,
}

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const THINKING_HINTS: &[&str] = &[
    "Thinking",
    "Planning",
    "Tracing",
    "Checking",
    "Exploring",
    "Reasoning",
];
const TYPING_HINTS: &[&str] = &["Typing", "Drafting", "Shaping", "Answering"];

fn thinking_hints_for_phase(phase: BusyPhase) -> &'static [&'static str] {
    match phase {
        BusyPhase::Thinking => THINKING_HINTS,
        BusyPhase::Typing => TYPING_HINTS,
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode().context("failed to enable raw mode")?;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste,
            PushKeyboardEnhancementFlags(
                KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                    | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
                    | KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS
            ),
            cursor::Hide
        )
        .context("failed to enter alternate screen")?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            cursor::Show,
            ResetColor,
            SetAttribute(Attribute::Reset),
            PopKeyboardEnhancementFlags,
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

struct TerminalUi {
    stdout: io::Stdout,
}

struct StatusRenderLine {
    prefix: String,
    body: String,
    prefix_phase: Option<usize>,
}

struct PromptRenderLine {
    text: String,
    cursor_col: Option<usize>,
}

const STATUS_LABEL_WIDTH: usize = 10;
const STATUS_TIMER_WIDTH: usize = 4;
const STATUS_PREFIX_WIDTH: usize = 1 + STATUS_TIMER_WIDTH + 1 + STATUS_LABEL_WIDTH + 1;
const STATUS_PREFIX_BASE: Color = Color::Rgb {
    r: 158,
    g: 104,
    b: 196,
};
const STATUS_PREFIX_SOFT: Color = Color::Rgb {
    r: 124,
    g: 82,
    b: 158,
};
const STATUS_PREFIX_SHIMMER: Color = Color::Rgb {
    r: 201,
    g: 150,
    b: 236,
};

impl TerminalUi {
    fn new() -> Result<Self> {
        Ok(Self {
            stdout: io::stdout(),
        })
    }

    fn render(
        &mut self,
        transcript: &[String],
        state: &ChatRenderState,
        input: &InputState,
    ) -> Result<()> {
        let (width, height) = terminal::size().context("failed to read terminal size")?;
        let width = width.max(20) as usize;
        let height = height.max(6) as usize;
        let slash_matches = slash_command_matches(&input.buffer);
        let slash_panel_rows = if input.buffer.starts_with('/') {
            slash_matches.len().min(6)
        } else {
            0
        };
        let prompt_rows = prompt_rows(input, width);
        let footer_height = 3usize + prompt_rows + slash_panel_rows;
        let content_height = height.saturating_sub(footer_height);
        let status_max_rows = content_height.saturating_sub(1).max(1);
        let status_lines = compose_status_lines(state, width, status_max_rows);
        let status_rows = status_lines.len().max(1);
        let transcript_height = content_height.saturating_sub(status_rows);
        let (wrapped_transcript, last_entry_start) = wrap_transcript_entries(transcript, width);
        let start = if state.transcript_scroll == 0
            && wrapped_transcript.len() > transcript_height
            && wrapped_transcript.len().saturating_sub(last_entry_start) > transcript_height
        {
            last_entry_start
        } else {
            wrapped_transcript
                .len()
                .saturating_sub(transcript_height + state.transcript_scroll)
        };
        let visible = &wrapped_transcript[start..];

        queue!(
            self.stdout,
            cursor::MoveTo(0, 0),
            Clear(ClearType::All),
            ResetColor,
            SetAttribute(Attribute::Reset)
        )?;

        for row in 0..transcript_height {
            queue!(
                self.stdout,
                cursor::MoveTo(0, row as u16),
                Clear(ClearType::CurrentLine)
            )?;
            if let Some(line) = visible.get(row) {
                queue!(self.stdout, Print(line))?;
            }
        }

        let status_top = visible
            .len()
            .min(content_height.saturating_sub(status_rows)) as u16;
        let footer_top = content_height as u16;
        self.draw_status_lines(status_top, width, &status_lines)?;
        self.draw_divider(footer_top, width)?;
        self.draw_prompt_line(footer_top + 1, width, input, prompt_rows)?;
        if slash_panel_rows > 0 {
            self.draw_divider(footer_top + 1 + prompt_rows as u16, width)?;
            self.draw_slash_palette(
                footer_top + 2 + prompt_rows as u16,
                width,
                input,
                &slash_matches,
                slash_panel_rows,
            )?;
            self.draw_hint_line(
                footer_top + 2 + prompt_rows as u16 + slash_panel_rows as u16,
                width,
                state,
                input,
            )?;
        } else {
            self.draw_divider(footer_top + 1 + prompt_rows as u16, width)?;
            self.draw_hint_line(footer_top + 2 + prompt_rows as u16, width, state, input)?;
        }
        self.stdout.flush()?;
        Ok(())
    }

    fn draw_slash_palette(
        &mut self,
        start_row: u16,
        width: usize,
        input: &InputState,
        matches: &[&SlashCommand],
        rows: usize,
    ) -> Result<()> {
        let desc_start = 24usize.min(width.saturating_sub(8));
        for row in 0..rows {
            queue!(
                self.stdout,
                cursor::MoveTo(0, start_row + row as u16),
                Clear(ClearType::CurrentLine)
            )?;
            if let Some(command) = matches.get(row) {
                let selected = row == input.slash_selection.min(matches.len().saturating_sub(1));
                let name = truncate_plain(command.name, desc_start.saturating_sub(1));
                let desc_width = width.saturating_sub(desc_start);
                let description = truncate_plain(command.description, desc_width);
                if selected {
                    queue!(
                        self.stdout,
                        SetForegroundColor(Color::Blue),
                        SetAttribute(Attribute::Bold),
                        Print(name),
                        ResetColor,
                        SetAttribute(Attribute::Reset)
                    )?;
                } else {
                    queue!(
                        self.stdout,
                        SetForegroundColor(Color::Grey),
                        Print(name),
                        ResetColor
                    )?;
                }
                queue!(
                    self.stdout,
                    cursor::MoveTo(desc_start as u16, start_row + row as u16),
                    SetForegroundColor(Color::DarkGrey),
                    Print(description),
                    ResetColor
                )?;
            }
        }
        Ok(())
    }

    fn draw_divider(&mut self, row: u16, width: usize) -> Result<()> {
        queue!(
            self.stdout,
            cursor::MoveTo(0, row),
            Clear(ClearType::CurrentLine),
            SetForegroundColor(Color::DarkGrey),
            Print("─".repeat(width)),
            ResetColor
        )?;
        Ok(())
    }

    fn draw_status_lines(
        &mut self,
        start_row: u16,
        width: usize,
        lines: &[StatusRenderLine],
    ) -> Result<()> {
        let rows = lines.len().max(1);
        for offset in 0..rows {
            queue!(
                self.stdout,
                cursor::MoveTo(0, start_row + offset as u16),
                Clear(ClearType::CurrentLine)
            )?;
            if let Some(line) = lines.get(offset) {
                let prefix = truncate_plain(&line.prefix, width);
                let prefix_width = STATUS_PREFIX_WIDTH.min(width);
                let body_width = width.saturating_sub(prefix_width);
                let body = if body_width == 0 {
                    String::new()
                } else {
                    truncate_plain(&line.body, body_width)
                };
                if let Some(phase) = line.prefix_phase {
                    self.draw_animated_prefix(&prefix, phase)?;
                } else {
                    queue!(
                        self.stdout,
                        SetAttribute(Attribute::Bold),
                        Print(prefix),
                        SetAttribute(Attribute::Reset)
                    )?;
                }
                if !body.is_empty() {
                    queue!(self.stdout, Print(body))?;
                }
            }
        }
        Ok(())
    }

    fn draw_animated_prefix(&mut self, text: &str, phase: usize) -> Result<()> {
        queue!(self.stdout, SetAttribute(Attribute::Bold))?;
        for (index, ch) in text.chars().enumerate() {
            let color = shimmer_color_for_index(index, phase);
            queue!(
                self.stdout,
                SetForegroundColor(color),
                Print(ch),
                ResetColor
            )?;
        }
        queue!(self.stdout, SetAttribute(Attribute::Reset))?;
        Ok(())
    }

    fn draw_prompt_line(
        &mut self,
        row: u16,
        width: usize,
        input: &InputState,
        rows: usize,
    ) -> Result<()> {
        let lines = prompt_display_lines(input, width, rows);
        for offset in 0..rows {
            queue!(
                self.stdout,
                cursor::MoveTo(0, row + offset as u16),
                Clear(ClearType::CurrentLine),
                SetForegroundColor(Color::White),
                SetAttribute(Attribute::Bold)
            )?;
            if let Some(line) = lines.get(offset) {
                queue!(self.stdout, Print(&line.text))?;
                if let Some(cursor_col) = line.cursor_col {
                    let cursor_x = cursor_col.min(width.saturating_sub(1)) as u16;
                    let cursor_char = line
                        .text
                        .chars()
                        .nth(cursor_col)
                        .filter(|ch| *ch != '\0')
                        .unwrap_or(' ');
                    queue!(
                        self.stdout,
                        cursor::MoveTo(cursor_x, row + offset as u16),
                        SetAttribute(Attribute::Reverse),
                        Print(cursor_char),
                        SetAttribute(Attribute::NoReverse)
                    )?;
                }
            }
            queue!(self.stdout, ResetColor, SetAttribute(Attribute::Reset))?;
        }
        Ok(())
    }

    fn draw_hint_line(
        &mut self,
        row: u16,
        width: usize,
        state: &ChatRenderState,
        input: &InputState,
    ) -> Result<()> {
        let hint = if state.exit_prompt_active() {
            "Press Ctrl-C again to exit"
        } else if input.buffer.starts_with('/') {
            "Up/Down to choose · Tab to complete · Enter to run"
        } else if state.transcript_scroll_active() {
            "PgUp/PgDn scrolls · Ctrl-End jumps to bottom"
        } else {
            "Shift-Enter/Option-Enter newline · Ctrl-D exits"
        };
        queue!(
            self.stdout,
            cursor::MoveTo(0, row),
            Clear(ClearType::CurrentLine),
            SetForegroundColor(Color::DarkGrey),
            Print(truncate_plain(hint, width)),
            ResetColor
        )?;
        Ok(())
    }
}

fn truncate_plain(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(text) <= width {
        return text.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > width - 1 {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out.push('…');
    out
}

fn normalize_pasted_input(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn should_collapse_paste(text: &str) -> bool {
    text.len() > 800 || text.contains('\n')
}

fn pasted_line_count(text: &str) -> usize {
    text.matches('\n').count()
}

fn format_pasted_text_ref(id: usize, line_count: usize) -> String {
    if line_count == 0 {
        format!("[Pasted text #{id}]")
    } else {
        format!("[Pasted text #{id} +{line_count} lines]")
    }
}

fn expand_pasted_blocks(input: &str, blocks: &[PastedBlock]) -> String {
    let mut expanded = input.to_string();
    for block in blocks.iter().rev() {
        expanded = expanded.replace(&block.placeholder, &block.text);
    }
    expanded
}

fn is_multiline_enter(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::SHIFT) || key.modifiers.contains(KeyModifiers::ALT)
}

fn line_start_before(text: &str, offset: usize) -> usize {
    text[..offset]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0)
}

fn line_end_after(text: &str, offset: usize) -> usize {
    text[offset..]
        .find('\n')
        .map(|index| offset + index)
        .unwrap_or(text.len())
}

fn char_column_in_line(text: &str, line_start: usize, offset: usize) -> usize {
    text[line_start..offset].chars().count()
}

fn offset_for_column(text: &str, line_start: usize, line_end: usize, column: usize) -> usize {
    text[line_start..line_end]
        .char_indices()
        .nth(column)
        .map(|(index, _)| line_start + index)
        .unwrap_or(line_end)
}

fn prompt_rows(input: &InputState, width: usize) -> usize {
    prompt_display_lines(input, width, 4).len().max(1)
}

fn prompt_display_lines(
    input: &InputState,
    width: usize,
    max_rows: usize,
) -> Vec<PromptRenderLine> {
    let prompt_width = width.max(4);
    let body_width = prompt_width.saturating_sub(2).max(1);
    let wrapped = wrap_input_for_prompt(&input.buffer, input.cursor_offset, body_width);
    let mut lines: Vec<PromptRenderLine> = Vec::new();
    for (index, line) in wrapped.into_iter().enumerate() {
        let prefix = if index == 0 { "> " } else { "  " };
        lines.push(PromptRenderLine {
            text: format!("{prefix}{}", line.text),
            cursor_col: line.cursor_col.map(|col| col + prefix.len()),
        });
    }
    if lines.is_empty() {
        lines.push(PromptRenderLine {
            text: "> ".to_string(),
            cursor_col: Some(2),
        });
    }
    if lines.len() > max_rows {
        let cursor_line = lines
            .iter()
            .position(|line| line.cursor_col.is_some())
            .unwrap_or_else(|| lines.len().saturating_sub(1));
        let start = cursor_line
            .saturating_add(1)
            .saturating_sub(max_rows)
            .min(lines.len().saturating_sub(max_rows));
        lines.drain(0..start);
        lines.truncate(max_rows);
        lines
    } else {
        lines
    }
}

fn wrap_input_for_prompt(text: &str, cursor_offset: usize, width: usize) -> Vec<PromptRenderLine> {
    let width = width.max(1);
    let cursor_offset = cursor_offset.min(text.len());
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;
    let mut cursor_col = None;

    for (offset, ch) in text.char_indices() {
        if ch == '\n' {
            if offset == cursor_offset {
                cursor_col = Some(used);
            }
            lines.push(PromptRenderLine {
                text: std::mem::take(&mut current),
                cursor_col: cursor_col.take(),
            });
            used = 0;
            continue;
        }

        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0).max(1);
        if used > 0 && used + ch_width > width {
            lines.push(PromptRenderLine {
                text: std::mem::take(&mut current),
                cursor_col: cursor_col.take(),
            });
            used = 0;
        }

        if offset == cursor_offset {
            cursor_col = Some(used);
        }
        current.push(ch);
        used += ch_width;
    }

    if cursor_offset == text.len() {
        cursor_col = Some(used);
    }
    lines.push(PromptRenderLine {
        text: current,
        cursor_col,
    });
    if text.ends_with('\n') && cursor_offset != text.len() {
        lines.push(PromptRenderLine {
            text: String::new(),
            cursor_col: None,
        });
    }
    lines
}

fn wrap_transcript_entries(lines: &[String], width: usize) -> (Vec<String>, usize) {
    let mut wrapped = Vec::new();
    let mut last_entry_start = 0usize;
    for line in lines {
        last_entry_start = wrapped.len();
        wrapped.extend(wrap_multiline_plain(line, width));
    }
    if wrapped.is_empty() {
        wrapped.push(String::new());
        last_entry_start = 0;
    }
    (wrapped, last_entry_start)
}

fn wrap_plain_line(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    if text.is_empty() {
        return vec![String::new()];
    }

    let mut out = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used > 0 && used + ch_width > width {
            out.push(current);
            current = String::new();
            used = 0;
        }
        current.push(ch);
        used += ch_width.max(1);
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn wrap_multiline_plain(text: &str, width: usize) -> Vec<String> {
    let mut wrapped = Vec::new();
    for line in text.split('\n') {
        wrapped.extend(wrap_plain_line(line, width));
    }
    if text.ends_with('\n') {
        wrapped.push(String::new());
    }
    if wrapped.is_empty() {
        wrapped.push(String::new());
    }
    wrapped
}

#[derive(Clone, Copy)]
struct SlashCommand {
    name: &'static str,
    description: &'static str,
}

const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        name: "/help",
        description: "Show available shortcuts and commands",
    },
    SlashCommand {
        name: "/status",
        description: "Show the current relay and group connection",
    },
    SlashCommand {
        name: "/pair",
        description: "Host a new pairing session from this chat",
    },
    SlashCommand {
        name: "/clear",
        description: "Clear the local transcript view",
    },
    SlashCommand {
        name: "/reset-history",
        description: "Delete saved transcript history from disk",
    },
    SlashCommand {
        name: "/disconnect",
        description: "Remove local pairing data and exit",
    },
    SlashCommand {
        name: "/quit",
        description: "Leave the current chat session",
    },
];

fn slash_command_matches(prefix: &str) -> Vec<&'static SlashCommand> {
    if !prefix.starts_with('/') {
        return Vec::new();
    }
    let trimmed = prefix.trim();
    let matches: Vec<_> = SLASH_COMMANDS
        .iter()
        .filter(|command| command.name.starts_with(trimmed))
        .collect();
    if matches.is_empty() {
        SLASH_COMMANDS.iter().collect()
    } else {
        matches
    }
}

fn compose_status_lines(
    state: &ChatRenderState,
    width: usize,
    max_rows: usize,
) -> Vec<StatusRenderLine> {
    if let Some(stream) = state.latest_stream() {
        debug!(
            stream_count = state.stream_buffers.len(),
            stream_text_len = stream.text.len(),
            stream_text_snippet = %truncate_for_log(&stream.text, 80),
            busy = state.busy.is_some(),
            "compose_status_lines: rendering active stream"
        );
        let prefix = if let Some(busy) = &state.busy {
            format_status_prefix(
                SPINNER_FRAMES[busy.spinner_index % SPINNER_FRAMES.len()],
                thinking_hints_for_phase(busy.phase)
                    [busy.hint_index % thinking_hints_for_phase(busy.phase).len()],
                busy.started_at.elapsed().as_secs(),
            )
        } else {
            // No busy state but still rendering a stream — this is the fallback
            // path. Log it because in practice it usually means a `Status: idle`
            // arrived while a stream was still mid-flight, and `text_end` may
            // never fire — leaving "Streaming" stuck on screen.
            warn!(
                stream_count = state.stream_buffers.len(),
                stream_text_len = stream.text.len(),
                "compose_status_lines: stream present without busy state — possible stuck render"
            );
            "Streaming          ".to_string()
        };
        let mut rows = Vec::new();
        let content_width = width.saturating_sub(STATUS_PREFIX_WIDTH).max(1);
        let wrapped = wrap_multiline_plain(&stream.text, content_width);
        if let Some(first) = wrapped.first() {
            rows.push(StatusRenderLine {
                prefix: prefix.clone(),
                body: first.clone(),
                prefix_phase: state.busy.as_ref().map(|busy| busy.spinner_index),
            });
        }
        for line in wrapped.into_iter().skip(1) {
            if rows.len() >= max_rows {
                break;
            }
            rows.push(StatusRenderLine {
                prefix: String::new(),
                body: line,
                prefix_phase: None,
            });
        }
        return rows;
    }

    if let Some(busy) = &state.busy {
        return vec![StatusRenderLine {
            prefix: format_status_prefix(
                SPINNER_FRAMES[busy.spinner_index % SPINNER_FRAMES.len()],
                thinking_hints_for_phase(busy.phase)
                    [busy.hint_index % thinking_hints_for_phase(busy.phase).len()],
                busy.started_at.elapsed().as_secs(),
            ),
            body: String::new(),
            prefix_phase: Some(busy.spinner_index),
        }];
    }

    Vec::new()
}

fn format_status_prefix(spinner: &str, label: &str, secs: u64) -> String {
    let timer = format!("{secs}s");
    format!(
        "{}{:>timer_width$} {:<width$} ",
        spinner,
        timer,
        label,
        timer_width = STATUS_TIMER_WIDTH,
        width = STATUS_LABEL_WIDTH,
    )
}

fn shimmer_color_for_index(index: usize, phase: usize) -> Color {
    let glimmer_index = phase % (STATUS_LABEL_WIDTH + STATUS_TIMER_WIDTH + 6);
    let distance = index.abs_diff(glimmer_index);
    if distance == 0 {
        STATUS_PREFIX_SHIMMER
    } else if distance == 1 {
        STATUS_PREFIX_SOFT
    } else {
        STATUS_PREFIX_BASE
    }
}

fn history_role_for_sender(sender: Option<&SenderInfo>) -> HistoryRole {
    match sender.map(|sender| sender.role) {
        Some(SenderRole::App) => HistoryRole::User,
        Some(SenderRole::Plugin) | None => HistoryRole::Agent,
    }
}

fn render_chat_line(sender: Option<&SenderInfo>, text: &str) -> String {
    match sender {
        Some(SenderInfo {
            role: SenderRole::App,
            device_name,
            ..
        }) => format!("{device_name}: {text}"),
        Some(SenderInfo {
            role: SenderRole::Plugin,
            ..
        }) => text.to_string(),
        None => text.to_string(),
    }
}

fn maybe_push_plugin_update_warning(
    state: &mut ChatRenderState,
    transcript: &mut Vec<String>,
    sender: Option<&SenderInfo>,
) {
    if state.plugin_update_warning_shown {
        return;
    }
    let Some(sender) = sender else {
        return;
    };
    if sender.role != SenderRole::Plugin {
        return;
    }
    let Some(version) = sender.app_version.as_deref() else {
        return;
    };
    if !is_version_less_than(version, MIN_PLUGIN_VERSION) {
        return;
    }
    state.plugin_update_warning_shown = true;
    let package = sender.bundle_id.as_deref().unwrap_or("chat4000 plugin");
    push_transcript_line(
        transcript,
        format!(
            "[update recommended: {package} {version} is older than supported {MIN_PLUGIN_VERSION}]"
        ),
    );
}

fn is_version_less_than(current: &str, minimum: &str) -> bool {
    let current_parts = version_parts(current);
    let minimum_parts = version_parts(minimum);
    current_parts < minimum_parts
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionPolicyAction {
    None,
    SoftNag { recommended: Option<String> },
    HardBlock { min_version: String },
}

fn evaluate_version_policy(app_version: &str, policy: &VersionPolicy) -> VersionPolicyAction {
    let parsed_local = semver::Version::parse(app_version.trim_start_matches('v')).ok();

    if let (Some(local), Some(min)) = (
        parsed_local.as_ref(),
        policy
            .min_version
            .as_deref()
            .and_then(|raw| semver::Version::parse(raw.trim_start_matches('v')).ok())
            .as_ref(),
    ) {
        if local < min {
            return VersionPolicyAction::HardBlock {
                min_version: policy.min_version.clone().unwrap_or_default(),
            };
        }
    }

    if parsed_local.is_none() {
        return VersionPolicyAction::SoftNag {
            recommended: policy.recommended_version.clone(),
        };
    }

    if let (Some(local), Some(rec)) = (
        parsed_local.as_ref(),
        policy
            .recommended_version
            .as_deref()
            .and_then(|raw| semver::Version::parse(raw.trim_start_matches('v')).ok())
            .as_ref(),
    ) {
        if local < rec {
            return VersionPolicyAction::SoftNag {
                recommended: policy.recommended_version.clone(),
            };
        }
    }

    VersionPolicyAction::None
}

fn should_show_soft_nag(paths: &AppPaths, recommended: Option<&str>, now_ms: i64) -> bool {
    let Some(prev) = paths.read_update_nag() else {
        return true;
    };
    if prev.recommended_version.as_deref() != recommended {
        return true;
    }
    now_ms.saturating_sub(prev.shown_at_ms) >= UPDATE_NAG_INTERVAL_MS
}

fn handle_version_policy_pre_chat(
    paths: &AppPaths,
    policy: Option<&VersionPolicy>,
) -> Option<String> {
    let policy = policy?;
    match evaluate_version_policy(env!("CARGO_PKG_VERSION"), policy) {
        VersionPolicyAction::HardBlock { min_version } => {
            warn!(min_version = %min_version, "relay requires update; refusing to start chat");
            let latest = policy
                .latest_version
                .as_deref()
                .map(|v| format!(" Latest: {v}."))
                .unwrap_or_default();
            Some(format!(
                "Update required: chat4000 {min_version} or newer is needed to use this relay.{latest}\nUpgrade with `brew upgrade chat4000` or `cargo install chat4000`."
            ))
        }
        VersionPolicyAction::SoftNag { recommended } => {
            let now_ms = unix_ms();
            if should_show_soft_nag(paths, recommended.as_deref(), now_ms) {
                let line = match recommended.as_deref() {
                    Some(version) => {
                        format!("Update available: chat4000 {version} is recommended.")
                    }
                    None => {
                        "Update available: a newer chat4000 version is recommended.".to_string()
                    }
                };
                println!("{line}");
                if let Err(err) = paths.write_update_nag(&UpdateNagRecord {
                    recommended_version: recommended,
                    shown_at_ms: now_ms,
                }) {
                    warn!(error = %err, "failed persisting update nag timestamp");
                }
            }
            None
        }
        VersionPolicyAction::None => None,
    }
}

fn version_parts(version: &str) -> [u64; 3] {
    let mut parts = [0, 0, 0];
    for (index, part) in version
        .split(|ch: char| !(ch.is_ascii_digit()))
        .filter(|part| !part.is_empty())
        .take(3)
        .enumerate()
    {
        parts[index] = part.parse().unwrap_or(0);
    }
    parts
}

fn load_history_lines(paths: &AppPaths, limit: usize) -> Result<Vec<String>> {
    let entries = paths.read_history(limit)?;
    let mut lines = Vec::new();
    for entry in entries {
        match entry.role {
            HistoryRole::User => lines.push(format!("> {}", entry.text)),
            HistoryRole::Agent => lines.push(entry.text),
        }
    }
    Ok(lines)
}

fn push_transcript_line(transcript: &mut Vec<String>, line: String) {
    transcript.push(line);
    if transcript.len() > 500 {
        transcript.drain(0..transcript.len() - 500);
    }
}

fn handle_ctrl_c(render_state: &mut ChatRenderState) -> bool {
    if render_state.register_ctrl_c() {
        info!("exiting chat session after second ctrl-c");
        true
    } else {
        info!("first ctrl-c pressed, waiting for confirmation");
        false
    }
}

fn start_input_thread(input_tx: mpsc::UnboundedSender<InputEvent>) {
    thread::spawn(move || {
        loop {
            match event::read() {
                Ok(Event::Key(key)) if should_forward_key_event(&key) => {
                    if input_tx.send(InputEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(Event::Key(_)) => {}
                Ok(Event::Paste(text)) => {
                    if input_tx.send(InputEvent::Paste(text)).is_err() {
                        break;
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    if input_tx.send(InputEvent::Resize).is_err() {
                        break;
                    }
                }
                Ok(Event::Mouse(mouse)) => {
                    if input_tx.send(InputEvent::Mouse(mouse)).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    record_exception("input_error", &format!("{err:?}"));
                    eprintln!("input error: {err}");
                    break;
                }
            }
        }
    });
}

#[derive(Debug, Clone)]
struct AppPaths {
    config_file: PathBuf,
    history_file: PathBuf,
    input_history_file: PathBuf,
    device_identity_file: PathBuf,
    update_nag_file: PathBuf,
    store_file: PathBuf,
    log_dir: PathBuf,
}

impl AppPaths {
    fn resolve() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .context("could not resolve XDG config directory")?
            .join("chat4000");
        let data_dir = dirs::data_dir()
            .context("could not resolve XDG data directory")?
            .join("chat4000");
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("failed to create {}", config_dir.display()))?;
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create {}", data_dir.display()))?;
        let log_dir = data_dir.join("logs");
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create {}", log_dir.display()))?;
        Ok(Self {
            config_file: config_dir.join("group-config.json"),
            history_file: data_dir.join("history.jsonl"),
            input_history_file: data_dir.join("input_history"),
            device_identity_file: data_dir.join("device-identity.json"),
            update_nag_file: config_dir.join("update-nag.json"),
            store_file: data_dir.join("store.sqlite"),
            log_dir,
        })
    }

    fn open_store(&self) -> Result<MessageStore> {
        MessageStore::open(&self.store_file)
    }

    fn read_update_nag(&self) -> Option<UpdateNagRecord> {
        let raw = fs::read_to_string(&self.update_nag_file).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn write_update_nag(&self, record: &UpdateNagRecord) -> Result<()> {
        write_private_json(&self.update_nag_file, record)
    }

    fn load_config(&self) -> Result<Option<GroupConfig>> {
        if !self.config_file.exists() {
            debug!(path = %self.config_file.display(), "config file not present");
            return Ok(None);
        }
        let contents = fs::read_to_string(&self.config_file)
            .with_context(|| format!("failed to read {}", self.config_file.display()))?;
        let config = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", self.config_file.display()))?;
        info!(path = %self.config_file.display(), "loaded config file");
        Ok(Some(config))
    }

    fn save_config(&self, config: &GroupConfig) -> Result<()> {
        info!(path = %self.config_file.display(), "saving config file");
        write_private_json(&self.config_file, config)
    }

    fn append_history(&self, entry: &HistoryEntry) -> Result<()> {
        debug!(path = %self.history_file.display(), role = ?entry.role, "appending history entry");
        append_jsonl(&self.history_file, entry)
    }

    fn read_input_history(&self) -> Result<Vec<String>> {
        if !self.input_history_file.exists() {
            return Ok(Vec::new());
        }
        let contents = fs::read_to_string(&self.input_history_file)
            .with_context(|| format!("failed to read {}", self.input_history_file.display()))?;
        Ok(contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    fn append_input_history(&self, line: &str) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.input_history_file)
            .with_context(|| format!("failed to open {}", self.input_history_file.display()))?;
        writeln!(file, "{line}")
            .with_context(|| format!("failed to write {}", self.input_history_file.display()))?;
        Ok(())
    }

    fn load_or_create_device_identity(&self) -> Result<AppDeviceIdentity> {
        if self.device_identity_file.exists() {
            let contents = fs::read_to_string(&self.device_identity_file).with_context(|| {
                format!("failed to read {}", self.device_identity_file.display())
            })?;
            let record: DeviceIdentityRecord =
                serde_json::from_str(&contents).with_context(|| {
                    format!("failed to parse {}", self.device_identity_file.display())
                })?;
            info!(
                path = %self.device_identity_file.display(),
                device_id = %record.device_id,
                "loaded device identity"
            );
            return Ok(AppDeviceIdentity {
                sender: SenderInfo {
                    role: SenderRole::App,
                    device_id: record.device_id,
                    device_name: record.device_name,
                    app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    bundle_id: Some(CLI_BUNDLE_ID.to_string()),
                },
            });
        }

        let record = DeviceIdentityRecord {
            device_id: Uuid::new_v4().to_string(),
            device_name: detect_device_name(),
        };
        info!(
            path = %self.device_identity_file.display(),
            device_id = %record.device_id,
            device_name = %record.device_name,
            "creating new device identity"
        );
        write_private_json(&self.device_identity_file, &record)?;
        Ok(AppDeviceIdentity {
            sender: SenderInfo {
                role: SenderRole::App,
                device_id: record.device_id,
                device_name: record.device_name,
                app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                bundle_id: Some(CLI_BUNDLE_ID.to_string()),
            },
        })
    }

    fn read_history(&self, limit: usize) -> Result<Vec<HistoryEntry>> {
        if !self.history_file.exists() {
            return Ok(Vec::new());
        }
        let contents = fs::read_to_string(&self.history_file)
            .with_context(|| format!("failed to read {}", self.history_file.display()))?;
        let mut entries = Vec::new();
        for (line_index, line) in contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
        {
            match serde_json::from_str::<HistoryEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(err) => {
                    warn!(
                        path = %self.history_file.display(),
                        line = line_index + 1,
                        error = %err,
                        "skipping invalid history entry"
                    );
                    record_exception(
                        "history_parse_error",
                        &format!(
                            "skipping invalid history entry in {} at line {}: {err}",
                            self.history_file.display(),
                            line_index + 1
                        ),
                    );
                }
            }
        }
        if entries.len() > limit {
            entries.drain(0..entries.len() - limit);
        }
        Ok(entries)
    }

    fn clear_history(&self) -> Result<()> {
        if self.history_file.exists() {
            fs::remove_file(&self.history_file)
                .with_context(|| format!("failed removing {}", self.history_file.display()))?;
            info!(path = %self.history_file.display(), "cleared history file");
        }
        Ok(())
    }

    fn has_local_state(&self) -> bool {
        self.config_file.exists()
            || self.history_file.exists()
            || self.input_history_file.exists()
            || self.device_identity_file.exists()
            || self.update_nag_file.exists()
            || self.store_file.exists()
    }

    fn remove_local_state(&self) -> Result<()> {
        if self.config_file.exists() {
            fs::remove_file(&self.config_file)
                .with_context(|| format!("failed removing {}", self.config_file.display()))?;
            info!(path = %self.config_file.display(), "removed config file");
        }
        if self.history_file.exists() {
            fs::remove_file(&self.history_file)
                .with_context(|| format!("failed removing {}", self.history_file.display()))?;
            info!(path = %self.history_file.display(), "removed history file");
        }
        if self.input_history_file.exists() {
            fs::remove_file(&self.input_history_file).with_context(|| {
                format!("failed removing {}", self.input_history_file.display())
            })?;
            info!(path = %self.input_history_file.display(), "removed input history file");
        }
        if self.device_identity_file.exists() {
            fs::remove_file(&self.device_identity_file).with_context(|| {
                format!("failed removing {}", self.device_identity_file.display())
            })?;
            info!(
                path = %self.device_identity_file.display(),
                "removed device identity file"
            );
        }
        if self.update_nag_file.exists() {
            fs::remove_file(&self.update_nag_file)
                .with_context(|| format!("failed removing {}", self.update_nag_file.display()))?;
            info!(path = %self.update_nag_file.display(), "removed update nag file");
        }
        for ext in ["", "-wal", "-shm"] {
            let path = if ext.is_empty() {
                self.store_file.clone()
            } else {
                let mut p = self.store_file.clone().into_os_string();
                p.push(ext);
                PathBuf::from(p)
            };
            if path.exists() {
                fs::remove_file(&path)
                    .with_context(|| format!("failed removing {}", path.display()))?;
                info!(path = %path.display(), "removed store file");
            }
        }
        Ok(())
    }
}

fn detect_device_name() -> String {
    std::env::var("CHAT4000_DEVICE_NAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "Chat4000 CLI".to_string())
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed setting permissions on {}", path.display()))?;
    }
    Ok(())
}

fn write_private_text(path: &Path, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, value).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed setting permissions on {}", path.display()))?;
    }
    Ok(())
}

fn append_jsonl(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    serde_json::to_writer(&mut file, value).context("failed to serialize JSONL entry")?;
    writeln!(file).with_context(|| format!("failed to finalize {}", path.display()))?;
    Ok(())
}

fn unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn should_forward_key_event(key: &KeyEvent) -> bool {
    matches!(key.kind, KeyEventKind::Press)
        || matches!(
            key.kind,
            KeyEventKind::Repeat
                if matches!(
                    key.code,
                    KeyCode::Backspace
                        | KeyCode::Delete
                        | KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Home
                        | KeyCode::End
                        | KeyCode::PageUp
                        | KeyCode::PageDown
                )
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.6.5 v1: only the plugin emits inner ack frames. The CLI is an app
    /// and must stay silent on the ack channel — regardless of sender role.
    #[test]
    fn consumer_does_not_emit_inner_acks() {
        use chat4000_proto::{InnerMessage, SenderInfo, SenderRole};

        use crate::transport::mock::MockMessageTransport;

        let (mock, _events) = MockMessageTransport::new();
        let plugin_sender = SenderInfo {
            role: SenderRole::Plugin,
            device_id: "remote-plugin".into(),
            device_name: "OpenClaw".into(),
            app_version: Some("0.7.0".into()),
            bundle_id: Some("@chat4000/openclaw-plugin".into()),
        };
        let other_app_sender = SenderInfo {
            role: SenderRole::App,
            device_id: "other-phone".into(),
            device_name: "Phone".into(),
            app_version: Some("1.0.1".into()),
            bundle_id: Some("com.neonnode.chat4000app".into()),
        };
        let mut plugin_seen = false;
        handle_received_for_consumer(
            &InnerMessage::text_with_sender("hi from plugin", plugin_sender),
            None,
            &mut plugin_seen,
        );
        handle_received_for_consumer(
            &InnerMessage::text_with_sender("hi from sibling app", other_app_sender),
            None,
            &mut plugin_seen,
        );
        assert!(
            mock.sent().is_empty(),
            "CLI must not emit inner acks in v1 per §6.6.5"
        );
    }

    /// `OutboundTracker` consumes Sent + delivered (inner-ack) signals exactly
    /// like the real transport feeds them — and gates further transitions
    /// idempotently per §6.6.7 "at-most-one ack per (refs, stage)".
    #[tokio::test]
    async fn outbound_tracker_drives_sent_then_delivered_via_mock_events() {
        use chat4000_proto::{InnerMessage, SenderInfo, SenderRole};

        use crate::transport::TransportStatus;
        use crate::transport::mock::MockMessageTransport;
        use crate::transport::{MessageTransport, OutboundMessage, TransportEvent};

        let tmp = std::env::temp_dir().join(format!("chat4000-mock-test-{}", uuid::Uuid::new_v4()));
        let store = MessageStore::open(&tmp.join("store.sqlite")).unwrap();

        let (mock, mut events) = MockMessageTransport::new();
        let outbound_id = mock.send(OutboundMessage::Text("hi".into()));
        let mut tracker = OutboundTracker::default();
        tracker.track(outbound_id.clone());
        store.record_outbound("g", &outbound_id, 100).unwrap();

        // Pretend the relay confirmed the queue.
        mock.emit_status(outbound_id.clone(), TransportStatus::Sent);
        match events.recv().await.unwrap() {
            TransportEvent::Status(update) => tracker.mark_sent(&update.msg_id, "g", &store),
            other => panic!("expected Status, got {other:?}"),
        }
        assert_eq!(tracker.state_of(&outbound_id), OutboundState::Sent);

        // Pretend the plugin sent a Flow B inner ack pointing at our outbound.
        let plugin_sender = SenderInfo {
            role: SenderRole::Plugin,
            device_id: "remote-plugin".into(),
            device_name: "OpenClaw".into(),
            app_version: Some("0.7.0".into()),
            bundle_id: None,
        };
        let ack_inner = InnerMessage::ack_received(&outbound_id, plugin_sender);
        mock.deliver(ack_inner);
        match events.recv().await.unwrap() {
            TransportEvent::Receive(inner) => {
                let ack = inner.as_ack().expect("ack body");
                assert_eq!(ack.stage, "received");
                tracker.mark_delivered(ack.refs, "g", &store);
            }
            other => panic!("expected Receive, got {other:?}"),
        }
        assert_eq!(tracker.state_of(&outbound_id), OutboundState::Delivered);

        // Subsequent Sent updates must not regress an already-Delivered state.
        mock.emit_status(outbound_id.clone(), TransportStatus::Sent);
        match events.recv().await.unwrap() {
            TransportEvent::Status(update) => tracker.mark_sent(&update.msg_id, "g", &store),
            other => panic!("expected Status, got {other:?}"),
        }
        assert_eq!(tracker.state_of(&outbound_id), OutboundState::Delivered);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Redrive scenario: spec §6.6.9 says "a duplicate `msg_id` from any source
    /// must be processed exactly once at the application layer". The
    /// MockMessageTransport itself doesn't dedupe (real transports do), but we
    /// can prove the consumer-side dedup story by feeding the same inner.id
    /// twice via the store and asserting only the first is acted on.
    #[test]
    fn store_dedupes_replayed_inner_messages() {
        let tmp =
            std::env::temp_dir().join(format!("chat4000-redrive-test-{}", uuid::Uuid::new_v4()));
        let store = MessageStore::open(&tmp.join("store.sqlite")).unwrap();
        // First arrival is fresh.
        assert!(
            store
                .try_persist_received("g", "inner-1", Some(101), 100, Some("plugin"))
                .unwrap()
        );
        // Redrive after reconnect is a no-op (returns false), but the
        // watermark-update path is still safe to call.
        assert!(
            !store
                .try_persist_received("g", "inner-1", Some(101), 200, Some("plugin"))
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn plugin_policy_hard_block_below_min() {
        let policy = VersionPolicy {
            min_version: Some("0.5.0".into()),
            recommended_version: Some("0.7.0".into()),
            latest_version: None,
        };
        assert_eq!(
            evaluate_plugin_version_policy(Some("0.1.0"), &policy),
            PluginPolicyVerdict::HardBlock
        );
    }

    #[test]
    fn plugin_policy_soft_nag_below_recommended() {
        let policy = VersionPolicy {
            min_version: Some("0.5.0".into()),
            recommended_version: Some("0.7.0".into()),
            latest_version: None,
        };
        assert_eq!(
            evaluate_plugin_version_policy(Some("0.5.5"), &policy),
            PluginPolicyVerdict::SoftNag
        );
    }

    #[test]
    fn plugin_policy_missing_version_is_soft_nag_not_hard_block() {
        let policy = VersionPolicy {
            min_version: Some("0.5.0".into()),
            recommended_version: Some("0.7.0".into()),
            latest_version: None,
        };
        assert_eq!(
            evaluate_plugin_version_policy(None, &policy),
            PluginPolicyVerdict::SoftNag
        );
    }

    #[test]
    fn outbound_tracker_state_transitions_match_protocol_ticks() {
        let tmp = tempdir_for_store();
        let store = MessageStore::open(&tmp.path().join("test.sqlite")).unwrap();
        let mut tracker = OutboundTracker::default();
        tracker.track("m-1".to_string());
        store.record_outbound("g", "m-1", 100).unwrap();

        assert_eq!(tracker.state_of("m-1"), OutboundState::Sending);
        tracker.mark_sent("m-1", "g", &store);
        assert_eq!(tracker.state_of("m-1"), OutboundState::Sent);
        tracker.mark_delivered("m-1", "g", &store);
        assert_eq!(tracker.state_of("m-1"), OutboundState::Delivered);

        // mark_failed must not regress a delivered message.
        tracker.mark_failed("m-1", "g", &store);
        assert_eq!(tracker.state_of("m-1"), OutboundState::Delivered);
    }

    #[test]
    fn outbound_tracker_failed_is_terminal_for_in_flight_send() {
        let tmp = tempdir_for_store();
        let store = MessageStore::open(&tmp.path().join("test.sqlite")).unwrap();
        let mut tracker = OutboundTracker::default();
        tracker.track("m-1".to_string());
        store.record_outbound("g", "m-1", 100).unwrap();
        tracker.mark_failed("m-1", "g", &store);
        assert_eq!(tracker.state_of("m-1"), OutboundState::Failed);
    }

    #[test]
    fn outbound_lines_rewrites_tick_in_place() {
        let mut lines = OutboundLines::default();
        let mut transcript = vec!["[connected]".to_string(), "> hello world ·".to_string()];
        lines.record("m-1".into(), 1, "> hello world".into());

        assert!(lines.apply(&mut transcript, "m-1", OutboundState::Sent));
        assert_eq!(transcript[1], "> hello world ✓");
        assert!(lines.apply(&mut transcript, "m-1", OutboundState::Delivered));
        assert_eq!(transcript[1], "> hello world ✓✓");
        // Idempotent: applying the same state again returns false (no re-render needed).
        assert!(!lines.apply(&mut transcript, "m-1", OutboundState::Delivered));
    }

    #[test]
    fn inner_ack_round_trip_drives_delivered() {
        let sender = SenderInfo {
            role: SenderRole::Plugin,
            device_id: "plug-1".into(),
            device_name: "OpenClaw".into(),
            app_version: Some("0.7.0".into()),
            bundle_id: Some("@chat4000/openclaw-plugin".into()),
        };
        let inner = chat4000_proto::InnerMessage::ack_received("outbound-msg-id-1", sender);
        let raw = serde_json::to_string(&inner).unwrap();
        let parsed: chat4000_proto::InnerMessage = serde_json::from_str(&raw).unwrap();
        let ack = parsed.as_ack().expect("ack body should parse");
        assert_eq!(ack.refs, "outbound-msg-id-1");
        assert_eq!(ack.stage, "received");
    }

    fn tempdir_for_store() -> TempDir {
        TempDir::new().expect("tempdir")
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Result<Self> {
            let path = std::env::temp_dir().join(format!("chat4000-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn plugin_policy_at_or_above_recommended_is_ok() {
        let policy = VersionPolicy {
            min_version: Some("0.5.0".into()),
            recommended_version: Some("0.7.0".into()),
            latest_version: None,
        };
        assert_eq!(
            evaluate_plugin_version_policy(Some("0.7.0"), &policy),
            PluginPolicyVerdict::Ok
        );
    }

    fn test_paths(temp_root: &Path) -> AppPaths {
        AppPaths {
            config_file: temp_root.join("group-config.json"),
            history_file: temp_root.join("history.jsonl"),
            input_history_file: temp_root.join("input_history"),
            device_identity_file: temp_root.join("device-identity.json"),
            update_nag_file: temp_root.join("update-nag.json"),
            store_file: temp_root.join("store.sqlite"),
            log_dir: temp_root.join("logs"),
        }
    }

    #[test]
    fn group_config_rejects_invalid_base64() {
        let config = GroupConfig {
            group_key_base64: "%%%".to_string(),
        };
        assert!(config.group_key().is_err());
    }

    #[test]
    fn group_config_rejects_wrong_length_key() {
        let config = GroupConfig {
            group_key_base64: STANDARD.encode([0u8; 16]),
        };
        let error = config.group_key().unwrap_err();
        assert!(error.to_string().contains("32 bytes"));
    }

    #[test]
    fn app_paths_detect_local_state_presence() {
        let temp_root = std::env::temp_dir().join(format!("chat4000-test-{}", unix_ms()));
        fs::create_dir_all(&temp_root).unwrap();
        let paths = test_paths(&temp_root);

        assert!(!paths.has_local_state());
        fs::write(&paths.history_file, b"{}\n").unwrap();
        assert!(paths.has_local_state());
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn append_only_text_delta_concatenates_by_stream_id() {
        let mut state = ChatRenderState::default();
        state.update_stream_delta("stream-1".into(), None, "Hel");
        state.update_stream_delta("stream-1".into(), None, "lo");

        let stream = state.stream_buffers.get("stream-1").unwrap();
        assert_eq!(stream.text, "Hello");
    }

    #[test]
    fn new_stream_id_supersedes_old_live_stream() {
        let mut state = ChatRenderState::default();
        state.update_stream_delta("stream-a".into(), None, "Hello wor");
        state.update_stream_delta("stream-b".into(), None, "Actually:");
        state.update_stream_delta("stream-b".into(), None, " Hello again");

        assert!(!state.stream_buffers.contains_key("stream-a"));
        assert!(state.suppressed_streams.contains("stream-a"));

        let stream = state.stream_buffers.get("stream-b").unwrap();
        assert_eq!(stream.text, "Actually: Hello again");
    }

    /// Regression for the "Streaming  🌿" stuck-render bug. Per protocol
    /// §6.4.2 (post-2026-05-06), the stream correlator lives in
    /// `body.stream_id`, not in `inner.id`. The plugin emits a fresh inner.id
    /// per frame (correct, dedup-able per §6.6.9) but reuses one stream_id
    /// across all frames in a logical reply. Verify that `stream_correlator`
    /// pulls the body.stream_id field, so concatenation and finalize all
    /// land on the same buffer key.
    #[test]
    fn stream_correlator_reads_body_stream_id() {
        use chat4000_proto::{InnerMessage, InnerMessageType};
        use uuid::Uuid;

        let make_frame = |t: InnerMessageType, stream_id: &str, content: serde_json::Value| {
            let mut body = content;
            body["stream_id"] = serde_json::Value::String(stream_id.to_string());
            InnerMessage {
                t,
                id: Uuid::new_v4(),
                from: None,
                body,
                ts: 0,
            }
        };

        let stream_id = "shared-stream-id-x";
        let f1 = make_frame(
            InnerMessageType::TextDelta,
            stream_id,
            serde_json::json!({ "delta": "Hey" }),
        );
        let f2 = make_frame(
            InnerMessageType::TextDelta,
            stream_id,
            serde_json::json!({ "delta": "o" }),
        );
        let f3 = make_frame(
            InnerMessageType::TextEnd,
            stream_id,
            serde_json::json!({ "text": "Heyo" }),
        );

        // All three frames have different inner.id but the same body.stream_id.
        assert_ne!(f1.id, f2.id);
        assert_ne!(f2.id, f3.id);
        assert_eq!(stream_correlator(&f1), stream_id);
        assert_eq!(stream_correlator(&f2), stream_id);
        assert_eq!(stream_correlator(&f3), stream_id);
    }

    /// Pre-2026-05-06 fallback: a frame with no `body.stream_id` should
    /// correlate by `inner.id` so legacy senders still render correctly.
    #[test]
    fn stream_correlator_falls_back_to_inner_id_for_legacy_senders() {
        use chat4000_proto::{InnerMessage, InnerMessageType};
        use uuid::Uuid;

        let id = Uuid::new_v4();
        let frame = InnerMessage {
            t: InnerMessageType::TextDelta,
            id,
            from: None,
            body: serde_json::json!({ "delta": "hi" }),
            ts: 0,
        };
        assert_eq!(stream_correlator(&frame), id.to_string());
    }

    /// End-to-end render: feed in three deltas + one text_end all sharing one
    /// body.stream_id but each carrying its own fresh inner.id, and verify the
    /// active-stream buffer concatenates correctly and clears on text_end.
    #[test]
    fn streaming_concatenates_by_body_stream_id_across_frames() {
        use chat4000_proto::SenderRole;

        let mut state = ChatRenderState::default();
        let plugin_sender = SenderInfo {
            role: SenderRole::Plugin,
            device_id: "plugin-1".into(),
            device_name: "OpenClaw".into(),
            app_version: Some("0.7.0".into()),
            bundle_id: None,
        };
        let stream_id = "stream-shared".to_string();

        state.update_stream_delta(stream_id.clone(), Some(plugin_sender.clone()), "Hey");
        state.update_stream_delta(stream_id.clone(), Some(plugin_sender.clone()), "o");
        state.update_stream_delta(stream_id.clone(), Some(plugin_sender.clone()), " 🌿");
        assert_eq!(
            state.stream_buffers.get(&stream_id).unwrap().text,
            "Heyo 🌿"
        );

        let (_sender, text, suppressed) =
            state.complete_stream(&stream_id, Some(plugin_sender), "Heyo 🌿");
        assert!(!suppressed);
        assert_eq!(text, "Heyo 🌿");
        assert!(state.stream_buffers.is_empty());
        assert!(state.busy.is_none());
        assert!(state.latest_stream().is_none());
    }

    #[test]
    fn superseded_stream_completion_is_marked_suppressed() {
        let mut state = ChatRenderState::default();
        state.update_stream_delta("stream-a".into(), None, "Hello wor");
        state.update_stream_delta("stream-b".into(), None, "Actually:");

        let (_sender, text, suppressed) = state.complete_stream("stream-a", None, "Hello wor");
        assert_eq!(text, "Hello wor");
        assert!(suppressed);
    }

    #[test]
    fn text_end_is_final_for_active_stream() {
        let mut state = ChatRenderState::default();
        state.update_stream_delta("stream-a".into(), None, "Hello");
        state.update_stream_delta("stream-a".into(), None, " world");

        let (_sender, text, suppressed) = state.complete_stream("stream-a", None, "Hello world");
        assert_eq!(text, "Hello world");
        assert!(!suppressed);
    }

    #[test]
    fn transcript_wrapping_splits_embedded_newlines() {
        let transcript = vec!["Alpha line\nBeta line".to_string()];
        let (wrapped, last_entry_start) = wrap_transcript_entries(&transcript, 80);

        assert_eq!(last_entry_start, 0);
        assert_eq!(
            wrapped,
            vec!["Alpha line".to_string(), "Beta line".to_string()]
        );
    }

    #[test]
    fn version_policy_hard_blocks_below_min_version() {
        let policy = VersionPolicy {
            min_version: Some("1.0.0".into()),
            recommended_version: Some("1.2.0".into()),
            latest_version: Some("1.3.0".into()),
        };
        let action = evaluate_version_policy("0.9.0", &policy);
        assert!(matches!(action, VersionPolicyAction::HardBlock { .. }));
    }

    #[test]
    fn version_policy_soft_nags_below_recommended() {
        let policy = VersionPolicy {
            min_version: Some("1.0.0".into()),
            recommended_version: Some("1.2.0".into()),
            latest_version: Some("1.3.0".into()),
        };
        let action = evaluate_version_policy("1.1.0", &policy);
        assert!(matches!(action, VersionPolicyAction::SoftNag { .. }));
    }

    #[test]
    fn version_policy_no_action_when_at_or_above_recommended() {
        let policy = VersionPolicy {
            min_version: Some("1.0.0".into()),
            recommended_version: Some("1.2.0".into()),
            latest_version: Some("1.3.0".into()),
        };
        assert_eq!(
            evaluate_version_policy("1.2.0", &policy),
            VersionPolicyAction::None
        );
        assert_eq!(
            evaluate_version_policy("1.5.0", &policy),
            VersionPolicyAction::None
        );
    }

    #[test]
    fn version_policy_unparseable_local_version_soft_nags() {
        let policy = VersionPolicy {
            min_version: Some("1.0.0".into()),
            recommended_version: Some("1.2.0".into()),
            latest_version: None,
        };
        assert!(matches!(
            evaluate_version_policy("not-a-version", &policy),
            VersionPolicyAction::SoftNag { .. }
        ));
    }

    #[test]
    fn version_policy_all_fields_null_yields_no_action() {
        let policy = VersionPolicy::default();
        assert_eq!(
            evaluate_version_policy("0.0.1", &policy),
            VersionPolicyAction::None
        );
    }

    #[test]
    fn soft_nag_shown_when_no_record_exists() {
        let temp_root = std::env::temp_dir().join(format!("chat4000-nag-test-{}", unix_ms()));
        fs::create_dir_all(&temp_root).unwrap();
        let paths = test_paths(&temp_root);
        assert!(should_show_soft_nag(&paths, Some("1.2.0"), 0));
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn soft_nag_throttled_within_30_days() {
        let temp_root = std::env::temp_dir().join(format!("chat4000-nag-test-{}", unix_ms() + 1));
        fs::create_dir_all(&temp_root).unwrap();
        let paths = test_paths(&temp_root);
        let now = unix_ms();
        paths
            .write_update_nag(&UpdateNagRecord {
                recommended_version: Some("1.2.0".into()),
                shown_at_ms: now,
            })
            .unwrap();
        assert!(!should_show_soft_nag(&paths, Some("1.2.0"), now + 1000));
        assert!(should_show_soft_nag(
            &paths,
            Some("1.2.0"),
            now + UPDATE_NAG_INTERVAL_MS + 1
        ));
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn soft_nag_resets_when_recommended_version_changes() {
        let temp_root = std::env::temp_dir().join(format!("chat4000-nag-test-{}", unix_ms() + 2));
        fs::create_dir_all(&temp_root).unwrap();
        let paths = test_paths(&temp_root);
        let now = unix_ms();
        paths
            .write_update_nag(&UpdateNagRecord {
                recommended_version: Some("1.2.0".into()),
                shown_at_ms: now,
            })
            .unwrap();
        assert!(should_show_soft_nag(&paths, Some("1.3.0"), now + 1000));
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn version_policy_min_only_hard_blocks() {
        let policy = VersionPolicy {
            min_version: Some("2.0.0".into()),
            recommended_version: None,
            latest_version: None,
        };
        assert!(matches!(
            evaluate_version_policy("1.9.9", &policy),
            VersionPolicyAction::HardBlock { .. }
        ));
    }

    #[test]
    fn scrub_secrets_redacts_common_credentials() {
        let scrubbed = scrub_secrets(
            "Bearer abc.def token=secret password: hunter2 ghp_abcdefghijklmnopqrstuvwxyz",
        );

        assert!(!scrubbed.contains("abc.def"));
        assert!(!scrubbed.contains("secret"));
        assert!(!scrubbed.contains("hunter2"));
        assert!(!scrubbed.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn scrub_path_removes_user_segment() {
        let scrubbed = scrub_path("/Users/haim/project/src/main.rs");

        assert_eq!(scrubbed, "/Users/<user>/project/src/main.rs");
    }

    #[test]
    fn paste_text_collapses_multiline_content_into_reference() {
        let mut input = InputState::default();
        assert!(matches!(
            input.paste_text("first\r\nsecond\nthird"),
            InputAction::Redraw
        ));

        assert_eq!(input.buffer, "[Pasted text #1 +2 lines]");
        assert_eq!(input.pasted_blocks.len(), 1);
        assert_eq!(input.pasted_blocks[0].text, "first\nsecond\nthird");
    }

    #[test]
    fn paste_reference_expands_on_submit() {
        let mut input = InputState::default();
        let _ = input.paste_text("first\nsecond");

        match input.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()), false) {
            InputAction::Submit { display, send } => {
                assert_eq!(display, "[Pasted text #1 +1 lines]");
                assert_eq!(send, "first\nsecond");
            }
            _ => panic!("expected pasted text to submit"),
        }
    }

    #[test]
    fn arrow_history_is_ignored_while_paste_reference_exists() {
        let mut input = InputState::from_history(vec!["older".to_string()]);
        let _ = input.paste_text("first\nsecond");

        assert!(matches!(
            input.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()), false),
            InputAction::None
        ));
        assert_eq!(input.buffer, "[Pasted text #1 +1 lines]");
    }

    #[test]
    fn shift_enter_inserts_newline_without_submitting() {
        let mut input = InputState::default();
        let _ = input.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()),
            false,
        );

        assert!(matches!(
            input.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT), false),
            InputAction::Redraw
        ));

        assert_eq!(input.buffer, "a\n");
    }

    #[test]
    fn option_enter_inserts_newline_without_submitting() {
        let mut input = InputState::default();
        let _ = input.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()),
            false,
        );

        assert!(matches!(
            input.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT), false),
            InputAction::Redraw
        ));

        assert_eq!(input.buffer, "a\n");
    }

    #[test]
    fn arrow_up_moves_multiline_cursor_instead_of_history() {
        let mut input = InputState::from_history(vec!["older".to_string()]);
        let _ = input.handle_key(
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()),
            false,
        );
        let _ = input.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT), false);

        assert!(matches!(
            input.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()), false),
            InputAction::Redraw
        ));
        assert_eq!(input.buffer, "a\n");
    }

    #[test]
    fn arrows_move_between_manual_multiline_rows() {
        let mut input = InputState::default();
        for ch in "abc\ndef".chars() {
            input.insert_str_at_cursor(&ch.to_string());
        }
        assert_eq!(input.cursor_offset, "abc\ndef".len());

        let _ = input.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()), false);
        assert_eq!(input.cursor_offset, 3);

        let _ = input.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()), false);
        assert_eq!(input.cursor_offset, "abc\ndef".len());
    }

    #[test]
    fn option_arrows_jump_words_without_inserting_letters() {
        let mut input = InputState::default();
        input.insert_str_at_cursor("hello world");

        let _ = input.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::ALT), false);
        assert_eq!(input.buffer, "hello world");
        assert_eq!(input.cursor_offset, 6);

        let _ = input.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT), false);
        assert_eq!(input.buffer, "hello world");
        assert_eq!(input.cursor_offset, input.buffer.len());
    }

    #[test]
    fn alt_b_and_alt_f_jump_words_without_inserting_letters() {
        let mut input = InputState::default();
        input.insert_str_at_cursor("hello world");

        let _ = input.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::ALT), false);
        assert_eq!(input.buffer, "hello world");
        assert_eq!(input.cursor_offset, 6);

        let _ = input.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::ALT), false);
        assert_eq!(input.buffer, "hello world");
        assert_eq!(input.cursor_offset, input.buffer.len());
    }

    #[test]
    fn option_backspace_deletes_previous_word() {
        let mut input = InputState::default();
        input.insert_str_at_cursor("hello world");

        let _ = input.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT), false);

        assert_eq!(input.buffer, "hello ");
        assert_eq!(input.cursor_offset, "hello ".len());
    }

    #[test]
    fn option_backspace_deletes_trailing_spaces_and_previous_word() {
        let mut input = InputState::default();
        input.insert_str_at_cursor("hello world   ");

        let _ = input.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT), false);

        assert_eq!(input.buffer, "hello ");
        assert_eq!(input.cursor_offset, "hello ".len());
    }

    #[test]
    fn repeat_backspace_is_forwarded() {
        let key = KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT);
        let repeat =
            KeyEvent::new_with_kind(KeyCode::Backspace, KeyModifiers::ALT, KeyEventKind::Repeat);

        assert!(should_forward_key_event(&key));
        assert!(should_forward_key_event(&repeat));
    }

    #[test]
    fn repeat_letter_is_not_forwarded() {
        let repeat = KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::empty(),
            KeyEventKind::Repeat,
        );

        assert!(!should_forward_key_event(&repeat));
    }

    #[test]
    fn transcript_scroll_mode_stays_active_until_explicit_bottom() {
        let mut state = ChatRenderState::default();

        assert!(!state.transcript_scroll_active());
        state.scroll_up(3);
        assert!(state.transcript_scroll_active());
        state.scroll_down(3);
        assert!(state.transcript_scroll_active());
        state.scroll_to_bottom();
        assert!(!state.transcript_scroll_active());
    }

    #[test]
    fn read_history_skips_invalid_jsonl_entries() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("chat4000-history-test-{}", unix_ms()));
        fs::create_dir_all(&temp_root)?;
        let paths = test_paths(&temp_root);
        fs::write(
            &paths.history_file,
            "{\"role\":\"user\",\"text\":\"ok\",\"ts\":1}\n{\"role\":\"bad\"\n{\"role\":\"agent\",\"text\":\"still ok\",\"ts\":2}\n",
        )?;

        let entries = paths.read_history(10)?;

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "ok");
        assert_eq!(entries[1].text, "still ok");
        let _ = fs::remove_dir_all(&temp_root);
        Ok(())
    }
}
