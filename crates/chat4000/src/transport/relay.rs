// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use chat4000_proto::{InnerMessageType, SenderInfo, VersionPolicy};
use chat4000_relay::{ConnectOptions, RelaySession, SessionEvent, connect_session};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::store::MessageStore;

use super::{
    ConnectionState, MessageTransport, OutboundMessage, StatusUpdate, TransportEvent,
    TransportEvents, TransportStatus,
};

/// Configuration captured at construction time. The transport owns its
/// connection lifecycle from `start` onward.
#[derive(Clone)]
pub struct TransportConfig {
    pub relay_url: String,
    pub group_id: String,
    pub group_key: Vec<u8>,
    pub device_id: String,
    pub sender: SenderInfo,
    pub app_id: Option<String>,
    pub app_version: Option<String>,
    pub release_channel: Option<String>,
    pub allow_self_signed_tls: bool,
    pub debug_acks: bool,
}

pub struct RelayMessageTransport {
    cmd_tx: mpsc::UnboundedSender<TransportCommand>,
    /// Latest known plugin version policy from the most recent `hello_ok`.
    plugin_version_policy: Arc<Mutex<Option<VersionPolicy>>>,
    /// Latest known app version policy from the most recent `hello_ok`.
    version_policy: Arc<Mutex<Option<VersionPolicy>>>,
}

#[derive(Debug)]
enum TransportCommand {
    Send {
        msg_id: String,
        outbound: OutboundMessage,
    },
    Disconnect,
}

impl RelayMessageTransport {
    /// Open a connection and start the event-loop task. Returns the running
    /// transport plus a single-consumer event stream.
    pub async fn start(
        config: TransportConfig,
        store: Arc<MessageStore>,
    ) -> Result<(Self, TransportEvents)> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<TransportCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<TransportEvent>();

        let plugin_policy = Arc::new(Mutex::new(None));
        let version_policy = Arc::new(Mutex::new(None));

        let task_state = TaskState {
            config: config.clone(),
            store: Arc::clone(&store),
            event_tx: event_tx.clone(),
            cmd_rx,
            seen_inner_ids: HashSet::new(),
            outbound_tracking: HashSet::new(),
            plugin_policy: Arc::clone(&plugin_policy),
            version_policy: Arc::clone(&version_policy),
        };

        // Eagerly attempt a first connection so callers learn early about
        // misconfigured endpoints / wrong group keys.
        let (session, last_acked_seq) = connect_initial(&config, &task_state.store).await?;
        if let Some(policy) = session.version_policy().cloned() {
            *version_policy.lock().expect("version policy poisoned") = Some(policy);
        }
        if let Some(policy) = session.plugin_version_policy().cloned() {
            *plugin_policy.lock().expect("plugin policy poisoned") = Some(policy);
        }
        let _ = event_tx.send(TransportEvent::Connection(ConnectionState::Connected));

        tokio::spawn(run_event_loop(task_state, session, last_acked_seq));

        Ok((
            Self {
                cmd_tx,
                plugin_version_policy: plugin_policy,
                version_policy,
            },
            event_rx,
        ))
    }

    pub fn version_policy(&self) -> Option<VersionPolicy> {
        self.version_policy
            .lock()
            .expect("version policy poisoned")
            .clone()
    }

    pub fn plugin_version_policy(&self) -> Option<VersionPolicy> {
        self.plugin_version_policy
            .lock()
            .expect("plugin policy poisoned")
            .clone()
    }
}

impl MessageTransport for RelayMessageTransport {
    fn send(&self, msg: OutboundMessage) -> String {
        let msg_id = Uuid::new_v4().to_string();
        // SAFETY: dropping the result is fine — if the task is gone the consumer
        // already saw a `Disconnected` / `Failed` connection event.
        let _ = self.cmd_tx.send(TransportCommand::Send {
            msg_id: msg_id.clone(),
            outbound: msg,
        });
        msg_id
    }

    fn disconnect(&self) {
        let _ = self.cmd_tx.send(TransportCommand::Disconnect);
    }
}

struct TaskState {
    config: TransportConfig,
    store: Arc<MessageStore>,
    event_tx: mpsc::UnboundedSender<TransportEvent>,
    cmd_rx: mpsc::UnboundedReceiver<TransportCommand>,
    /// Inner-id dedup table. Spec §6.6.9: every inner.id processed exactly once.
    seen_inner_ids: HashSet<String>,
    /// Outbound msg_ids we've sent through this transport instance — used to
    /// match `relay_recv_ack` frames to `StatusUpdate { Sent }` events.
    outbound_tracking: HashSet<String>,
    plugin_policy: Arc<Mutex<Option<VersionPolicy>>>,
    version_policy: Arc<Mutex<Option<VersionPolicy>>>,
}

async fn connect_initial(
    config: &TransportConfig,
    store: &Arc<MessageStore>,
) -> Result<(RelaySession, u64)> {
    let last_acked_seq = store.last_acked_seq(&config.group_id, &config.device_id)?;
    let session = connect_session(
        &config.relay_url,
        &config.group_id,
        &config.device_id,
        config.group_key.clone(),
        Some(config.sender.clone()),
        ConnectOptions {
            app_id: config.app_id.clone(),
            app_version: config.app_version.clone(),
            release_channel: config.release_channel.clone(),
            last_acked_seq: (last_acked_seq > 0).then_some(last_acked_seq),
            allow_self_signed_tls: config.allow_self_signed_tls,
            ..Default::default()
        },
    )
    .await?;
    Ok((session, last_acked_seq))
}

async fn run_event_loop(mut state: TaskState, initial_session: RelaySession, initial_acked: u64) {
    let mut session = initial_session;
    let mut pump = AckPump::new(initial_acked);
    let mut reconnect_delay = 2u64;

    loop {
        match drive_session(&mut state, &mut session, &mut pump).await {
            DriveOutcome::Disconnect => {
                debug!("transport task: graceful disconnect");
                break;
            }
            DriveOutcome::Reconnect(reason) => {
                let _ = state
                    .event_tx
                    .send(TransportEvent::Connection(ConnectionState::Reconnecting));
                warn!(reason = %reason, delay_secs = reconnect_delay, "transport reconnecting");
                tokio::time::sleep(Duration::from_secs(reconnect_delay)).await;
                reconnect_delay = (reconnect_delay * 2).min(60);

                match connect_initial(&state.config, &state.store).await {
                    Ok((new_session, new_acked)) => {
                        if let Some(policy) = new_session.version_policy().cloned() {
                            *state.version_policy.lock().expect("poisoned") = Some(policy);
                        }
                        if let Some(policy) = new_session.plugin_version_policy().cloned() {
                            *state.plugin_policy.lock().expect("poisoned") = Some(policy);
                        }
                        let _ = state
                            .event_tx
                            .send(TransportEvent::Connection(ConnectionState::Connected));
                        session = new_session;
                        pump = AckPump::new(new_acked);
                        reconnect_delay = 2;
                    }
                    Err(err) => {
                        error!(error = ?err, "reconnect attempt failed");
                        let _ = state.event_tx.send(TransportEvent::Connection(
                            ConnectionState::Failed(err.to_string()),
                        ));
                        // Loop again with backoff.
                    }
                }
            }
        }
    }

    // Final flush: emit any pending recv_acks before tearing down.
    if let Some(up_to) = pump.flush_now() {
        if session.ack_aware() {
            let _ = session.send_recv_ack(up_to, vec![]);
            debug!(up_to_seq = up_to, "final recv_ack on transport shutdown");
        }
    }
    let _ = state
        .event_tx
        .send(TransportEvent::Connection(ConnectionState::Disconnected));
}

enum DriveOutcome {
    Disconnect,
    Reconnect(String),
}

async fn drive_session(
    state: &mut TaskState,
    session: &mut RelaySession,
    pump: &mut AckPump,
) -> DriveOutcome {
    loop {
        let pump_deadline = pump.until_flush();

        tokio::select! {
            // Consumer command channel.
            cmd = state.cmd_rx.recv() => {
                match cmd {
                    Some(TransportCommand::Send { msg_id, outbound }) => {
                        if let Err(err) = handle_outbound(session, &msg_id, outbound, &mut state.outbound_tracking, &state.config) {
                            warn!(error = %err, "transport send failed locally");
                            let _ = state.event_tx.send(TransportEvent::Status(StatusUpdate {
                                msg_id,
                                status: TransportStatus::Failed,
                            }));
                        }
                    }
                    Some(TransportCommand::Disconnect) | None => {
                        return DriveOutcome::Disconnect;
                    }
                }
            }

            // Periodic ack-pump tick (only sleeps until the pending batch's
            // 50 ms debounce expires).
            _ = wait_optional(pump_deadline) => {
                flush_pump_if_due(pump, session, state.config.debug_acks);
            }

            // Underlying relay session events.
            event = session.next_event() => {
                let Some(event) = event else {
                    return DriveOutcome::Reconnect("session closed".to_string());
                };
                match event {
                    SessionEvent::Connected => {}
                    SessionEvent::Disconnected(reason) => {
                        return DriveOutcome::Reconnect(reason);
                    }
                    SessionEvent::RelayRecvAck { msg_id, queued_for } => {
                        if state.config.debug_acks {
                            eprintln!(
                                "[ack] relay_recv_ack msg_id={msg_id} queued_for={queued_for:?}"
                            );
                        }
                        if state.outbound_tracking.remove(&msg_id) {
                            let _ = state.event_tx.send(TransportEvent::Status(StatusUpdate {
                                msg_id,
                                status: TransportStatus::Sent,
                            }));
                        } else {
                            // Could be an ack for a cross-session redrive; surface anyway.
                            let _ = state.event_tx.send(TransportEvent::Status(StatusUpdate {
                                msg_id,
                                status: TransportStatus::Sent,
                            }));
                        }
                    }
                    SessionEvent::InnerMessage { inner, seq } => {
                        let inner_id = inner.id.to_string();
                        let role = inner.from.as_ref().map(|s| match s.role {
                            chat4000_proto::SenderRole::App => "app",
                            chat4000_proto::SenderRole::Plugin => "plugin",
                        });
                        let newly = match state.store.try_persist_received(
                            &state.config.group_id,
                            &inner_id,
                            seq,
                            inner.ts,
                            role,
                        ) {
                            Ok(v) => v,
                            Err(err) => {
                                error!(error = ?err, "failed to persist inbound message");
                                continue;
                            }
                        };
                        if let Some(seq_v) = seq {
                            pump.note_persisted(seq_v);
                            if newly {
                                let _ = state.store.set_last_acked_seq(
                                    &state.config.group_id,
                                    &state.config.device_id,
                                    seq_v,
                                );
                            }
                            if session.ack_aware() {
                                if let Some(up_to) = pump.try_flush() {
                                    if let Err(err) = session.send_recv_ack(up_to, vec![]) {
                                        warn!(error = %err, "failed to send recv_ack");
                                    } else if state.config.debug_acks {
                                        eprintln!("[ack] recv_ack up_to_seq={up_to}");
                                    }
                                }
                            }
                        }
                        // Dedup: only forward an inner message to the consumer once.
                        if !state.seen_inner_ids.insert(inner_id) {
                            debug!(message_id = %inner.id, "deduping repeat inner.id");
                            continue;
                        }
                        let _ = state.event_tx.send(TransportEvent::Receive(inner));
                    }
                }
            }
        }
    }
}

fn flush_pump_if_due(pump: &mut AckPump, session: &RelaySession, debug_acks: bool) {
    if let Some(up_to) = pump.try_flush() {
        if session.ack_aware() {
            if let Err(err) = session.send_recv_ack(up_to, vec![]) {
                warn!(error = %err, "failed to send debounced recv_ack");
            } else if debug_acks {
                eprintln!("[ack] recv_ack up_to_seq={up_to} (debounce)");
            }
        }
    }
}

async fn wait_optional(deadline: Option<Duration>) {
    match deadline {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn handle_outbound(
    session: &RelaySession,
    msg_id: &str,
    outbound: OutboundMessage,
    tracking: &mut HashSet<String>,
    config: &TransportConfig,
) -> Result<()> {
    use chat4000_proto::{InnerMessage, SenderInfo as ProtoSender};
    let sender: ProtoSender = config.sender.clone();
    let inner = match outbound {
        OutboundMessage::Text(text) => {
            let mut inner = InnerMessage::text_with_sender(text, sender);
            inner.id = Uuid::parse_str(msg_id).unwrap_or_else(|_| Uuid::new_v4());
            inner
        }
        OutboundMessage::TextDelta { stream_id, delta } => {
            let id = Uuid::parse_str(&stream_id).unwrap_or_else(|_| Uuid::new_v4());
            chat4000_proto::InnerMessage {
                t: InnerMessageType::TextDelta,
                id,
                from: Some(sender),
                body: serde_json::json!({ "delta": delta }),
                ts: now_ms(),
            }
        }
        OutboundMessage::TextEnd {
            stream_id,
            text,
            reset,
        } => {
            let id = Uuid::parse_str(&stream_id).unwrap_or_else(|_| Uuid::new_v4());
            let mut body = serde_json::json!({ "text": text });
            if let Some(r) = reset {
                body["reset"] = serde_json::Value::Bool(r);
            }
            chat4000_proto::InnerMessage {
                t: InnerMessageType::TextEnd,
                id,
                from: Some(sender),
                body,
                ts: now_ms(),
            }
        }
        OutboundMessage::Status(status) => {
            let mut inner = InnerMessage::new(
                InnerMessageType::Status,
                Some(sender),
                serde_json::json!({ "status": status }),
            );
            inner.id = Uuid::parse_str(msg_id).unwrap_or_else(|_| inner.id);
            inner
        }
        OutboundMessage::Ack { refs, stage } => {
            let mut inner = InnerMessage::new(
                InnerMessageType::Ack,
                Some(sender),
                serde_json::json!({
                    "refs": refs,
                    "stage": stage.as_str(),
                }),
            );
            inner.id = Uuid::parse_str(msg_id).unwrap_or_else(|_| inner.id);
            inner
        }
    };

    // Persisting outbound for status correlation: track msg_id we want a Sent
    // confirmation for. Status / Ack frames are not user content but we still
    // emit Sent on relay_recv_ack so consumers can audit if they care.
    tracking.insert(msg_id.to_string());

    // Encryption + outer-envelope wrapping happens inside RelaySession.
    let plaintext = serde_json::to_vec(&inner)?;
    let encrypted = chat4000_crypto::encrypt(&plaintext, &config.group_key)?;
    // Decide notify_if_offline per §6.3: only `text` (and image/audio if ever
    // added) should request offline push.
    let notify = matches!(inner.t, InnerMessageType::Text);
    let outgoing = chat4000_proto::RelayOutgoing::msg(
        encrypted.nonce,
        encrypted.ciphertext,
        msg_id,
        Some(notify),
    )?;
    session_send(session, outgoing)?;
    info!(msg_id, kind = ?inner.t, "transport queued outbound inner");
    Ok(())
}

fn session_send(session: &RelaySession, frame: String) -> Result<()> {
    // RelaySession exposes `send_text` but we want raw envelope control here.
    // The cleanest path is to reuse send_text-style behaviour by going through
    // the public API: encode an InnerMessage, and let RelaySession encrypt + ship.
    // To avoid double-encrypting, we use a private-ish hook: pretend it's a
    // text send to reuse the writer channel. Instead, here we exposed a raw
    // queue helper via `send_recv_ack`-style API by adding `send_raw_envelope`.
    // RelaySession does not currently expose that, so instead we route every
    // outbound through `send_text` for Text, and use `send_inner_ack` /
    // synthesise others by direct envelope. To keep the diff small for this
    // refactor we use a thin shim: drop the prebuilt envelope into the writer
    // channel through the public `send_recv_ack` *plumbing* by forwarding it
    // via a freshly-added method. See `RelaySession::send_envelope`.
    session.send_envelope(frame)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

// -----------------------------------------------------------------------------
// AckPump: §6.6.3 Flow A debouncer (32 / 50 ms / shutdown flush).
// -----------------------------------------------------------------------------

struct AckPump {
    last_acked_seq: u64,
    pending_max: u64,
    pending_count: usize,
    last_persist_at: Option<std::time::Instant>,
}

const ACK_BATCH_THRESHOLD: usize = 32;
const ACK_DEBOUNCE: Duration = Duration::from_millis(50);

impl AckPump {
    fn new(last_acked_seq: u64) -> Self {
        Self {
            last_acked_seq,
            pending_max: last_acked_seq,
            pending_count: 0,
            last_persist_at: None,
        }
    }

    fn note_persisted(&mut self, seq: u64) {
        if seq > self.pending_max {
            self.pending_max = seq;
        }
        self.pending_count += 1;
        self.last_persist_at = Some(std::time::Instant::now());
    }

    fn try_flush(&mut self) -> Option<u64> {
        if self.pending_count == 0 {
            return None;
        }
        let elapsed_ok = self
            .last_persist_at
            .map(|t| t.elapsed() >= ACK_DEBOUNCE)
            .unwrap_or(false);
        if self.pending_count >= ACK_BATCH_THRESHOLD || elapsed_ok {
            return Some(self.commit());
        }
        None
    }

    fn flush_now(&mut self) -> Option<u64> {
        if self.pending_count == 0 {
            None
        } else {
            Some(self.commit())
        }
    }

    fn commit(&mut self) -> u64 {
        self.last_acked_seq = self.pending_max;
        self.pending_count = 0;
        self.last_persist_at = None;
        self.last_acked_seq
    }

    fn until_flush(&self) -> Option<Duration> {
        let last = self.last_persist_at?;
        let elapsed = last.elapsed();
        if elapsed >= ACK_DEBOUNCE {
            Some(Duration::from_millis(0))
        } else {
            Some(ACK_DEBOUNCE - elapsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_pump_flushes_on_threshold() {
        let mut pump = AckPump::new(0);
        for seq in 1..=ACK_BATCH_THRESHOLD as u64 {
            pump.note_persisted(seq);
        }
        assert_eq!(pump.try_flush(), Some(ACK_BATCH_THRESHOLD as u64));
        assert!(pump.try_flush().is_none());
    }

    #[test]
    fn ack_pump_flush_now_drains_partial_batch() {
        let mut pump = AckPump::new(10);
        pump.note_persisted(11);
        pump.note_persisted(12);
        assert_eq!(pump.flush_now(), Some(12));
        assert_eq!(pump.flush_now(), None);
    }
}
