// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.
//
// `MockMessageTransport` lets unit tests drive consumers (e.g. `cmd_send`'s
// reply loop, the chat session's render loop) without touching a real relay.
// It records every `send()` call so tests can assert outbound payloads, and
// exposes scripted "the relay just sent us X" / "the relay just acked Y"
// hooks.

use std::sync::{Arc, Mutex};

use chat4000_proto::InnerMessage;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::{
    ConnectionState, MessageTransport, OutboundMessage, StatusUpdate, TransportEvent,
    TransportEvents, TransportStatus,
};

#[derive(Debug, Clone)]
pub struct SentRecord {
    pub msg_id: String,
    pub message: OutboundMessage,
}

pub struct MockMessageTransport {
    sent: Arc<Mutex<Vec<SentRecord>>>,
    event_tx: mpsc::UnboundedSender<TransportEvent>,
}

impl MockMessageTransport {
    pub fn new() -> (Self, TransportEvents) {
        let (event_tx, event_rx) = mpsc::unbounded_channel::<TransportEvent>();
        (
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                event_tx,
            },
            event_rx,
        )
    }

    /// Snapshot of every outbound message the consumer has produced so far.
    pub fn sent(&self) -> Vec<SentRecord> {
        self.sent.lock().expect("mock sent poisoned").clone()
    }

    /// Pretend the relay just delivered an inner message to us.
    pub fn deliver(&self, inner: InnerMessage) {
        let _ = self.event_tx.send(TransportEvent::Receive(inner));
    }

    /// Pretend the relay just emitted a status update for one of our outbound msg_ids.
    pub fn emit_status(&self, msg_id: impl Into<String>, status: TransportStatus) {
        let _ = self.event_tx.send(TransportEvent::Status(StatusUpdate {
            msg_id: msg_id.into(),
            status,
        }));
    }

    /// Push a connection-state transition.
    pub fn emit_connection(&self, state: ConnectionState) {
        let _ = self.event_tx.send(TransportEvent::Connection(state));
    }
}

impl MessageTransport for MockMessageTransport {
    fn send(&self, msg: OutboundMessage) -> String {
        let msg_id = Uuid::new_v4().to_string();
        self.sent
            .lock()
            .expect("mock sent poisoned")
            .push(SentRecord {
                msg_id: msg_id.clone(),
                message: msg,
            });
        msg_id
    }

    fn disconnect(&self) {
        let _ = self
            .event_tx
            .send(TransportEvent::Connection(ConnectionState::Disconnected));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat4000_proto::{AckStage, InnerMessageType, SenderInfo, SenderRole};

    #[test]
    fn send_records_outbound_and_returns_unique_id() {
        let (transport, _events) = MockMessageTransport::new();
        let id1 = transport.send(OutboundMessage::Text("hello".into()));
        let id2 = transport.send(OutboundMessage::Text("world".into()));
        assert_ne!(id1, id2);
        let sent = transport.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].msg_id, id1);
        assert!(matches!(sent[0].message, OutboundMessage::Text(ref t) if t == "hello"));
    }

    #[tokio::test]
    async fn deliver_pushes_inner_message_to_consumer() {
        let (transport, mut events) = MockMessageTransport::new();
        let sender = SenderInfo {
            role: SenderRole::Plugin,
            device_id: "plug".into(),
            device_name: "OpenClaw".into(),
            app_version: Some("0.7.0".into()),
            bundle_id: None,
        };
        let inner = InnerMessage::text_with_sender("hi", sender);
        let inner_id = inner.id;
        transport.deliver(inner);
        match events.recv().await.unwrap() {
            TransportEvent::Receive(got) => {
                assert_eq!(got.id, inner_id);
                assert_eq!(got.t, InnerMessageType::Text);
            }
            other => panic!("expected Receive, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_status_drives_sent_callback() {
        let (transport, mut events) = MockMessageTransport::new();
        let id = transport.send(OutboundMessage::Text("x".into()));
        transport.emit_status(id.clone(), TransportStatus::Sent);
        match events.recv().await.unwrap() {
            TransportEvent::Status(update) => {
                assert_eq!(update.msg_id, id);
                assert_eq!(update.status, TransportStatus::Sent);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ack_outbound_passes_through_send() {
        let (transport, _events) = MockMessageTransport::new();
        transport.send(OutboundMessage::Ack {
            refs: "msg-1".into(),
            stage: AckStage::Received,
        });
        let sent = transport.sent();
        assert_eq!(sent.len(), 1);
        assert!(matches!(
            sent[0].message,
            OutboundMessage::Ack { ref refs, stage } if refs == "msg-1" && stage == AckStage::Received
        ));
    }
}
