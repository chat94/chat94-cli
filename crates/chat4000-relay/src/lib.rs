// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chat4000_crypto::{
    WrappedGroupKey as CryptoWrappedGroupKey, decrypt, derive_group_id, derive_pair_proof,
    derive_pairing_room_id, encrypt, generate_group_key, generate_joiner_keypair,
    generate_pairing_code, unwrap_group_key, wrap_group_key,
};
use chat4000_proto::{
    ClientRole, DEFAULT_RELAY_URL, HEARTBEAT_INTERVAL_SECS, HelloPayload, IncomingMessage,
    InnerMessage, MessageType, MsgPayload, PairDataMessage, PairingRole, RelayOutgoing, SenderInfo,
    VersionPolicy, WrappedGroupKey,
};
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use tokio::{net::TcpStream, sync::mpsc, task::JoinHandle};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async, connect_async_tls_with_config,
    tungstenite::protocol::Message,
};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub relay_url: String,
    pub group_id: String,
    pub allow_self_signed_tls: bool,
}

impl RelayConfig {
    pub fn new(
        group_id: impl Into<String>,
        relay_url: Option<String>,
        allow_self_signed_tls: bool,
    ) -> Result<Self> {
        let group_id = group_id.into();
        if group_id.is_empty() {
            bail!("group_id cannot be empty");
        }
        Ok(Self {
            relay_url: relay_url.unwrap_or_else(|| DEFAULT_RELAY_URL.to_string()),
            group_id,
            allow_self_signed_tls,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairJoinOptions {
    pub relay_url: String,
    pub code: String,
    pub allow_self_signed_tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairJoinResult {
    pub group_key: Vec<u8>,
    pub group_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairHostOptions {
    pub relay_url: String,
    pub group_key: Vec<u8>,
    pub code: Option<String>,
    pub allow_self_signed_tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairHostResult {
    pub code: String,
    pub room_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairHostStatus {
    Connecting,
    Waiting,
    JoinerReady,
    GrantSent,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Connected,
    InnerMessage(InnerMessage),
    Disconnected(String),
}

pub struct RelaySession {
    group_key: Vec<u8>,
    sender: Option<SenderInfo>,
    version_policy: Option<VersionPolicy>,
    send_tx: mpsc::UnboundedSender<String>,
    event_rx: mpsc::UnboundedReceiver<SessionEvent>,
    last_pong: Arc<Mutex<Instant>>,
    _reader: JoinHandle<()>,
    _writer: JoinHandle<()>,
    _heartbeat: JoinHandle<()>,
}

pub async fn join_pairing_session(opts: PairJoinOptions) -> Result<PairJoinResult> {
    info!(
        relay_url = %opts.relay_url,
        allow_self_signed_tls = opts.allow_self_signed_tls,
        "starting join pairing session"
    );
    let normalized_code = normalize_and_validate_pairing_code(&opts.code)?;

    let room_id = derive_pairing_room_id(&normalized_code);
    let keypair = generate_joiner_keypair();
    let mut initiator_salt_b64 = None;
    debug!(room_id = %room_id, "opening join pairing room");
    let mut socket = connect(&opts.relay_url, opts.allow_self_signed_tls).await?;

    send_json(
        &mut socket,
        RelayOutgoing::pair_open(PairingRole::Joiner, room_id.clone())?,
    )
    .await?;

    loop {
        match read_incoming(&mut socket).await? {
            IncomingMessage::PairOpenOk | IncomingMessage::PairReady => continue,
            IncomingMessage::PairCancel { reason } => {
                bail!(
                    "pairing cancelled{}",
                    reason
                        .as_deref()
                        .map(|reason| format!(": {reason}"))
                        .unwrap_or_default()
                );
            }
            IncomingMessage::PairData(PairDataMessage::Hello { salt }) => {
                debug!("received initiator hello during join pairing");
                initiator_salt_b64 = Some(salt.clone());
                send_json(
                    &mut socket,
                    RelayOutgoing::pair_join(STANDARD.encode(keypair.public_key))?,
                )
                .await?;
                let proof_b = derive_pair_proof(
                    &normalized_code,
                    &decode_b64(&salt)?,
                    &keypair.public_key,
                    "B",
                );
                send_json(&mut socket, RelayOutgoing::pair_proof_b(proof_b)?).await?;
            }
            IncomingMessage::PairData(PairDataMessage::Grant { proof, wrapped_key }) => {
                debug!("received grant during join pairing");
                let initiator_salt_b64 = initiator_salt_b64
                    .as_deref()
                    .context("received grant before initiator hello")?;
                let expected = derive_pair_proof(
                    &normalized_code,
                    &decode_b64(initiator_salt_b64)?,
                    &keypair.public_key,
                    "A",
                );
                if proof != expected {
                    error!("join pairing proof mismatch");
                    bail!("pairing proof mismatch");
                }

                let group_key =
                    unwrap_group_key(&into_crypto_wrapped_key(wrapped_key), &keypair.private_key)
                        .context("failed to unwrap group key")?;
                send_json(&mut socket, RelayOutgoing::pair_complete()?).await?;
                tokio::time::sleep(Duration::from_millis(300)).await;
                info!("join pairing completed successfully");
                return Ok(PairJoinResult {
                    group_id: derive_group_id(&group_key),
                    group_key,
                });
            }
            IncomingMessage::PairData(_) => continue,
            other => debug!("ignoring unexpected pairing message: {:?}", other),
        }
    }
}

pub async fn host_pairing_session<F>(
    opts: PairHostOptions,
    mut on_status: F,
) -> Result<PairHostResult>
where
    F: FnMut(PairHostStatus, &str),
{
    info!(
        relay_url = %opts.relay_url,
        allow_self_signed_tls = opts.allow_self_signed_tls,
        "starting host pairing session"
    );
    if opts.group_key.len() != 32 {
        bail!("group key must be 32 bytes");
    }

    let code = opts.code.unwrap_or_else(generate_pairing_code);
    let normalized_code = normalize_and_validate_pairing_code(&code)?;
    let room_id = derive_pairing_room_id(&normalized_code);
    let initiator_salt = generate_group_key();
    let mut joiner_public_key = None;
    debug!(room_id = %room_id, "opening host pairing room");
    let mut socket = connect(&opts.relay_url, opts.allow_self_signed_tls).await?;

    on_status(PairHostStatus::Connecting, "Connecting to relay");
    send_json(
        &mut socket,
        RelayOutgoing::pair_open(PairingRole::Initiator, room_id.clone())?,
    )
    .await?;

    let result = PairHostResult {
        code,
        room_id: room_id.clone(),
    };

    loop {
        match read_incoming(&mut socket).await? {
            IncomingMessage::PairOpenOk => on_status(PairHostStatus::Waiting, "Waiting for peer"),
            IncomingMessage::PairReady => {
                debug!("joiner connected to host pairing room");
                on_status(PairHostStatus::JoinerReady, "Peer joined");
                send_json(
                    &mut socket,
                    RelayOutgoing::pair_hello(STANDARD.encode(initiator_salt))?,
                )
                .await?;
            }
            IncomingMessage::PairCancel { reason } => {
                bail!(
                    "pairing cancelled{}",
                    reason
                        .as_deref()
                        .map(|reason| format!(": {reason}"))
                        .unwrap_or_default()
                );
            }
            IncomingMessage::PairData(PairDataMessage::Join { salt }) => {
                debug!("received joiner public key");
                joiner_public_key = Some(decode_b64(&salt)?);
            }
            IncomingMessage::PairData(PairDataMessage::ProofB { proof }) => {
                debug!("received joiner proof");
                let joiner_public_key = joiner_public_key
                    .as_deref()
                    .context("received proof_b before join public key")?;
                let expected =
                    derive_pair_proof(&normalized_code, &initiator_salt, joiner_public_key, "B");
                if proof != expected {
                    error!("host pairing proof mismatch");
                    bail!("pairing proof mismatch");
                }
                let wrapped_key = wrap_group_key(&opts.group_key, joiner_public_key)?;
                let proof_a =
                    derive_pair_proof(&normalized_code, &initiator_salt, joiner_public_key, "A");
                send_json(
                    &mut socket,
                    RelayOutgoing::pair_grant(proof_a, into_proto_wrapped_key(wrapped_key))?,
                )
                .await?;
                on_status(PairHostStatus::GrantSent, "Key transferred");
            }
            IncomingMessage::PairComplete => {
                on_status(PairHostStatus::Completed, "Pairing complete");
                info!("host pairing completed successfully");
                return Ok(result);
            }
            IncomingMessage::PairData(_) => continue,
            other => debug!("ignoring unexpected pairing message: {:?}", other),
        }
    }
}

pub async fn connect_session(
    relay_url: &str,
    group_id: &str,
    device_id: &str,
    group_key: Vec<u8>,
    sender: Option<SenderInfo>,
    device_token: Option<String>,
    app_id: Option<String>,
    app_version: Option<String>,
    allow_self_signed_tls: bool,
) -> Result<RelaySession> {
    info!(
        relay_url = %relay_url,
        group_id = %group_id,
        device_id = %device_id,
        allow_self_signed_tls,
        "connecting relay session"
    );
    let mut socket = connect(relay_url, allow_self_signed_tls).await?;
    let hello = serde_json::to_string(&chat4000_proto::Envelope::new(
        MessageType::Hello,
        HelloPayload {
            role: ClientRole::App,
            group_id: group_id.to_string(),
            device_id: device_id.to_string(),
            device_token,
            app_id,
            app_version,
        },
    ))?;
    send_json(&mut socket, hello).await?;

    let version_policy = match read_incoming(&mut socket).await? {
        IncomingMessage::HelloOk(payload) => {
            debug!(
                has_version_policy = payload.version_policy.is_some(),
                "received hello_ok"
            );
            payload.version_policy
        }
        IncomingMessage::HelloError(payload) => {
            error!(code = %payload.code, message = %payload.message, "relay rejected hello");
            bail!(
                "relay rejected hello: {}: {}",
                payload.code,
                payload.message
            );
        }
        other => bail!("unexpected handshake response: {:?}", other),
    };

    let (write_half, read_half) = socket.split();
    let (send_tx, send_rx) = mpsc::unbounded_channel::<String>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<SessionEvent>();
    let last_pong = Arc::new(Mutex::new(Instant::now()));

    let writer = spawn_writer(write_half, send_rx);
    let reader = spawn_reader(
        read_half,
        group_key.clone(),
        Arc::clone(&last_pong),
        event_tx,
    );
    let heartbeat = spawn_heartbeat(send_tx.clone(), Arc::clone(&last_pong));
    info!("relay session handshake completed");

    Ok(RelaySession {
        group_key,
        sender,
        version_policy,
        send_tx,
        event_rx,
        last_pong,
        _reader: reader,
        _writer: writer,
        _heartbeat: heartbeat,
    })
}

impl RelaySession {
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.event_rx.recv().await
    }

    pub fn version_policy(&self) -> Option<&VersionPolicy> {
        self.version_policy.as_ref()
    }

    pub fn send_text(&self, text: &str) -> Result<()> {
        let inner = match &self.sender {
            Some(sender) => InnerMessage::text_with_sender(text, sender.clone()),
            None => InnerMessage::text(text),
        };
        let plaintext = serde_json::to_vec(&inner)?;
        let encrypted = encrypt(&plaintext, &self.group_key)?;
        self.send_tx
            .send(RelayOutgoing::msg(
                encrypted.nonce,
                encrypted.ciphertext,
                inner.id.to_string(),
            )?)
            .context("failed queueing outbound text")
    }

    pub fn latency_ok(&self) -> bool {
        self.last_pong
            .lock()
            .map(|last| last.elapsed() <= Duration::from_secs(HEARTBEAT_INTERVAL_SECS * 2))
            .unwrap_or(false)
    }
}

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn connect(relay_url: &str, allow_self_signed_tls: bool) -> Result<RelaySocket> {
    info!(
        relay_url = %relay_url,
        allow_self_signed_tls,
        "opening websocket connection"
    );
    let (socket, response) = if allow_self_signed_tls {
        connect_async_tls_with_config(
            relay_url,
            None,
            false,
            Some(Connector::Rustls(Arc::new(build_insecure_client_config()))),
        )
        .await
        .with_context(|| format!("failed to connect to relay at {relay_url}"))?
    } else {
        connect_async(relay_url)
            .await
            .with_context(|| format!("failed to connect to relay at {relay_url}"))?
    };
    debug!("connected to relay with HTTP status {}", response.status());
    Ok(socket)
}

async fn send_json(socket: &mut RelaySocket, json: String) -> Result<()> {
    debug!(payload = %json, "sending relay frame");
    socket
        .send(Message::Text(json.into()))
        .await
        .context("failed sending websocket frame")
}

async fn read_incoming(socket: &mut RelaySocket) -> Result<IncomingMessage> {
    loop {
        let message = socket
            .next()
            .await
            .context("relay closed websocket")?
            .context("websocket receive failed")?;

        match message {
            Message::Text(text) => {
                debug!(payload = %text, "received relay text frame");
                return Ok(IncomingMessage::parse(&text)?);
            }
            Message::Binary(bytes) => {
                let text = String::from_utf8(bytes.to_vec())
                    .context("relay sent non-UTF8 binary frame")?;
                debug!(payload = %text, "received relay binary frame");
                return Ok(IncomingMessage::parse(&text)?);
            }
            Message::Ping(payload) => {
                debug!("received relay ping");
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("failed responding to relay ping")?;
            }
            Message::Pong(_) => {
                debug!("received relay pong");
            }
            Message::Close(frame) => {
                let detail = frame
                    .map(|frame| format!("{} {}", frame.code, frame.reason))
                    .unwrap_or_else(|| "without close frame".to_string());
                error!(detail = %detail, "relay closed websocket during read");
                bail!("relay closed websocket {detail}");
            }
            Message::Frame(_) => {}
        }
    }
}

fn spawn_writer(
    mut write_half: SplitSink<RelaySocket, Message>,
    mut send_rx: mpsc::UnboundedReceiver<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(payload) = send_rx.recv().await {
            if payload.is_empty() {
                info!("writer received shutdown signal");
                let _ = write_half.send(Message::Close(None)).await;
                break;
            }
            if write_half
                .send(Message::Text(payload.into()))
                .await
                .is_err()
            {
                error!("relay writer failed to send frame");
                break;
            }
        }
    })
}

fn spawn_reader(
    mut read_half: SplitStream<RelaySocket>,
    group_key: Vec<u8>,
    last_pong: Arc<Mutex<Instant>>,
    event_tx: mpsc::UnboundedSender<SessionEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = event_tx.send(SessionEvent::Connected);
        while let Some(frame) = read_half.next().await {
            match frame {
                Ok(Message::Text(text)) => {
                    debug!(payload = %text, "reader received text frame");
                    if let Err(err) = handle_text_frame(&text, &group_key, &last_pong, &event_tx) {
                        error!(error = %err, "failed to handle text frame");
                        let _ = event_tx.send(SessionEvent::Disconnected(err.to_string()));
                        break;
                    }
                }
                Ok(Message::Binary(bytes)) => {
                    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                        debug!(payload = %text, "reader received binary frame");
                        if let Err(err) =
                            handle_text_frame(&text, &group_key, &last_pong, &event_tx)
                        {
                            error!(error = %err, "failed to handle binary frame");
                            let _ = event_tx.send(SessionEvent::Disconnected(err.to_string()));
                            break;
                        }
                    }
                }
                Ok(Message::Pong(_)) => {
                    debug!("reader received pong");
                    if let Ok(mut last) = last_pong.lock() {
                        *last = Instant::now();
                    }
                }
                Ok(Message::Ping(_)) => {
                    debug!("reader received ping");
                }
                Ok(Message::Close(frame)) => {
                    let detail = frame
                        .map(|frame| format!("relay closed websocket: {}", frame.reason))
                        .unwrap_or_else(|| "relay closed websocket".to_string());
                    warn!(detail = %detail, "reader observed relay close");
                    let _ = event_tx.send(SessionEvent::Disconnected(detail));
                    break;
                }
                Ok(Message::Frame(_)) => {}
                Err(err) => {
                    error!(error = %err, "reader websocket error");
                    let _ = event_tx.send(SessionEvent::Disconnected(err.to_string()));
                    break;
                }
            }
        }
    })
}

fn spawn_heartbeat(
    send_tx: mpsc::UnboundedSender<String>,
    last_pong: Arc<Mutex<Instant>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            let timed_out = last_pong
                .lock()
                .map(|last| last.elapsed() > Duration::from_secs(HEARTBEAT_INTERVAL_SECS * 2))
                .unwrap_or(false);
            if timed_out {
                warn!("heartbeat timed out");
                let _ = send_tx.send(String::new());
                break;
            }
            match RelayOutgoing::ping() {
                Ok(ping) => {
                    if send_tx.send(ping).is_err() {
                        warn!("failed to queue heartbeat ping");
                        break;
                    }
                }
                Err(err) => {
                    error!(error = %err, "failed to build heartbeat ping");
                    break;
                }
            }
        }
    })
}

fn handle_text_frame(
    text: &str,
    group_key: &[u8],
    last_pong: &Arc<Mutex<Instant>>,
    event_tx: &mpsc::UnboundedSender<SessionEvent>,
) -> Result<()> {
    match IncomingMessage::parse(text)? {
        IncomingMessage::Msg(MsgPayload {
            nonce, ciphertext, ..
        }) => {
            debug!("handling encrypted relay message");
            let plaintext = decrypt(&nonce, &ciphertext, group_key)?;
            let inner: InnerMessage = serde_json::from_slice(&plaintext)?;
            let _ = event_tx.send(SessionEvent::InnerMessage(inner));
        }
        IncomingMessage::Pong => {
            debug!("handling relay pong");
            if let Ok(mut last) = last_pong.lock() {
                *last = Instant::now();
            }
        }
        other => debug!("ignoring session message: {:?}", other),
    }
    Ok(())
}

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(input)?)
}

fn normalize_and_validate_pairing_code(code: &str) -> Result<String> {
    let invalid: Vec<char> = code
        .trim()
        .chars()
        .flat_map(char::to_uppercase)
        .filter(|ch| !matches!(ch, '-' | ' ' | '\t' | '\n' | '\r'))
        .filter(|ch| !chat4000_crypto::PAIRING_CODE_ALPHABET.contains(&(*ch as u8)))
        .collect();
    if !invalid.is_empty() {
        let invalid_chars = invalid
            .into_iter()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("pairing code contains invalid character(s): {invalid_chars}");
    }
    let normalized = chat4000_crypto::normalize_pairing_code(code);
    if normalized.len() != 8 {
        bail!("pairing code must normalize to 8 characters");
    }
    Ok(normalized)
}

fn build_insecure_client_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth()
}

fn into_crypto_wrapped_key(value: WrappedGroupKey) -> CryptoWrappedGroupKey {
    CryptoWrappedGroupKey {
        ephemeral_pub: value.ephemeral_pub,
        nonce: value.nonce,
        ciphertext: value.ciphertext,
    }
}

fn into_proto_wrapped_key(value: CryptoWrappedGroupKey) -> WrappedGroupKey {
    WrappedGroupKey {
        ephemeral_pub: value.ephemeral_pub,
        nonce: value.nonce,
        ciphertext: value.ciphertext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_config_rejects_empty_group_id() {
        assert!(RelayConfig::new("", None, false).is_err());
    }

    #[test]
    fn relay_config_uses_default_relay_url() {
        let config = RelayConfig::new("group-1", None, true).unwrap();
        assert_eq!(config.relay_url, DEFAULT_RELAY_URL);
        assert_eq!(config.group_id, "group-1");
        assert!(config.allow_self_signed_tls);
    }

    #[test]
    fn pairing_code_validation_normalizes_and_accepts_valid_input() {
        let normalized = normalize_and_validate_pairing_code("ab-cd 2346").unwrap();
        assert_eq!(normalized, "ABCD2346");
    }

    #[test]
    fn pairing_code_validation_rejects_short_input() {
        let error = normalize_and_validate_pairing_code("BAD").unwrap_err();
        assert!(error.to_string().contains("8 characters"));
    }

    #[test]
    fn pairing_code_validation_rejects_invalid_characters() {
        let error = normalize_and_validate_pairing_code("6FATQTTJ").unwrap_err();
        assert!(error.to_string().contains("invalid character"));
        assert!(error.to_string().contains("Q"));
    }
}
