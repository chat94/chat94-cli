// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.
//
// `MessageTransport` is the application-layer-facing facade described in
// chat4000 protocol §6.6.11. It hides:
//
//   - WebSocket lifecycle, hello/handshake, ping/pong, reconnect
//   - XChaCha20-Poly1305 encryption and outer-envelope wrapping
//   - The §6.6 ack flow: outer `seq`, debounced cumulative `recv_ack`,
//     durable `last_acked_seq` checkpoint
//   - Outbound `msg_id` tracking → `Sent` status on `relay_recv_ack`
//   - Dedup by `inner.id` before firing `Receive`
//
// Consumers see only typed `OutboundMessage` values they hand to `send()`,
// and a single stream of `TransportEvent`s. They never see `seq`, never call
// `recv_ack`, and never open a socket.

pub mod relay;

#[cfg(test)]
pub mod mock;

use chat4000_proto::{AckStage, InnerMessage};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum OutboundMessage {
    Text(String),
    TextDelta {
        stream_id: String,
        delta: String,
    },
    TextEnd {
        stream_id: String,
        text: String,
        reset: Option<bool>,
    },
    Status(String),
    /// Application-layer Flow B ack. Passes through the transport like any
    /// other inner message — the transport does not synthesize these.
    Ack {
        refs: String,
        stage: AckStage,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportStatus {
    Sent,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StatusUpdate {
    pub msg_id: String,
    pub status: TransportStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum TransportEvent {
    Receive(InnerMessage),
    Status(StatusUpdate),
    Connection(ConnectionState),
}

/// Channel-based facade. Implementations spawn whatever they need internally;
/// `send` is fire-and-forget and returns the wire `inner.id` immediately so the
/// consumer can correlate it with later `Status` and inner-`ack` events.
pub trait MessageTransport: Send + Sync {
    /// Returns the wire `inner.id`. Encryption, outbox, retries, and reconnect
    /// are the transport's responsibility.
    fn send(&self, msg: OutboundMessage) -> String;

    /// Best-effort graceful shutdown. After this returns, no further
    /// `TransportEvent`s will be emitted on the consumer channel.
    fn disconnect(&self);
}

pub type TransportEvents = mpsc::UnboundedReceiver<TransportEvent>;
