// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_SIZE: usize = 65_536;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_RELAY_URL: &str = "wss://relay.chat4000.com/ws";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    App,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderRole {
    App,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingRole {
    Initiator,
    Joiner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    PairOpen,
    PairOpenOk,
    PairReady,
    PairData,
    PairComplete,
    PairCancel,
    Challenge,
    ChallengeOk,
    Register,
    RegisterOk,
    RegisterError,
    Hello,
    HelloOk,
    HelloError,
    Msg,
    Ping,
    Pong,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T = Value> {
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(msg_type: MessageType, payload: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloPayload {
    pub role: ClientRole,
    pub group_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VersionPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HelloOkPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_terms_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_policy: Option<VersionPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub group_id: String,
    pub attestation: String,
    pub challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeOkPayload {
    pub nonce: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterOkPayload {
    pub group_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgPayload {
    pub nonce: String,
    pub ciphertext: String,
    pub msg_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairOpenPayload {
    pub role: PairingRole,
    pub room_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedGroupKey {
    pub ephemeral_pub: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairDataPayload {
    pub t: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<WrappedGroupKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairCompletePayload {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairCancelPayload {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerMessage {
    pub t: InnerMessageType,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<SenderInfo>,
    pub body: Value,
    pub ts: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    pub role: SenderRole,
    #[serde(rename = "device_id")]
    pub device_id: String,
    #[serde(rename = "device_name")]
    pub device_name: String,
    #[serde(
        rename = "app_version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub app_version: Option<String>,
    #[serde(rename = "bundle_id", default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerMessageType {
    Text,
    Image,
    Audio,
    TextDelta,
    TextEnd,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairDataMessage {
    Hello {
        salt: String,
    },
    Join {
        salt: String,
    },
    ProofB {
        proof: String,
    },
    Grant {
        proof: String,
        wrapped_key: WrappedGroupKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingMessage {
    PairOpenOk,
    PairReady,
    PairData(PairDataMessage),
    PairComplete,
    PairCancel { reason: Option<String> },
    ChallengeOk(ChallengeOkPayload),
    RegisterOk(RegisterOkPayload),
    RegisterError(ErrorPayload),
    HelloOk(HelloOkPayload),
    HelloError(ErrorPayload),
    Msg(MsgPayload),
    Pong,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("failed to parse JSON envelope")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported message type")]
    UnsupportedMessage,
    #[error("invalid pair_data payload")]
    InvalidPairData,
}

pub struct RelayOutgoing;

impl RelayOutgoing {
    pub fn hello(
        group_id: impl Into<String>,
        device_id: impl Into<String>,
        device_token: Option<String>,
        app_id: Option<String>,
        app_version: Option<String>,
    ) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::Hello,
            HelloPayload {
                role: ClientRole::App,
                group_id: group_id.into(),
                device_id: device_id.into(),
                device_token,
                app_id,
                app_version,
            },
        ))
    }

    pub fn challenge() -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::Challenge,
            serde_json::json!({}),
        ))
    }

    pub fn register(
        group_id: impl Into<String>,
        attestation: impl Into<String>,
        challenge: impl Into<String>,
    ) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::Register,
            RegisterPayload {
                group_id: group_id.into(),
                attestation: attestation.into(),
                challenge: challenge.into(),
            },
        ))
    }

    pub fn pair_open(role: PairingRole, room_id: impl Into<String>) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::PairOpen,
            PairOpenPayload {
                role,
                room_id: room_id.into(),
            },
        ))
    }

    pub fn pair_hello(salt: impl Into<String>) -> serde_json::Result<String> {
        Self::pair_data(PairDataPayload {
            t: "hello".into(),
            salt: Some(salt.into()),
            proof: None,
            wrapped_key: None,
        })
    }

    pub fn pair_join(salt: impl Into<String>) -> serde_json::Result<String> {
        Self::pair_data(PairDataPayload {
            t: "join".into(),
            salt: Some(salt.into()),
            proof: None,
            wrapped_key: None,
        })
    }

    pub fn pair_proof_b(proof: impl Into<String>) -> serde_json::Result<String> {
        Self::pair_data(PairDataPayload {
            t: "proof_b".into(),
            salt: None,
            proof: Some(proof.into()),
            wrapped_key: None,
        })
    }

    pub fn pair_grant(
        proof: impl Into<String>,
        wrapped_key: WrappedGroupKey,
    ) -> serde_json::Result<String> {
        Self::pair_data(PairDataPayload {
            t: "grant".into(),
            salt: None,
            proof: Some(proof.into()),
            wrapped_key: Some(wrapped_key),
        })
    }

    pub fn pair_complete() -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::PairComplete,
            PairCompletePayload {
                status: "ok".into(),
            },
        ))
    }

    pub fn pair_cancel(reason: Option<String>) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::PairCancel,
            PairCancelPayload { reason },
        ))
    }

    pub fn msg(
        nonce: impl Into<String>,
        ciphertext: impl Into<String>,
        msg_id: impl Into<String>,
    ) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(
            MessageType::Msg,
            MsgPayload {
                nonce: nonce.into(),
                ciphertext: ciphertext.into(),
                msg_id: msg_id.into(),
            },
        ))
    }

    pub fn ping() -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(MessageType::Ping, Value::Null))
    }

    fn pair_data(payload: PairDataPayload) -> serde_json::Result<String> {
        serde_json::to_string(&Envelope::new(MessageType::PairData, payload))
    }
}

impl IncomingMessage {
    pub fn parse(input: &str) -> Result<Self, ProtocolError> {
        let header: Envelope<Value> = serde_json::from_str(input)?;
        match header.msg_type {
            MessageType::PairOpenOk => Ok(Self::PairOpenOk),
            MessageType::PairReady => Ok(Self::PairReady),
            MessageType::PairComplete => Ok(Self::PairComplete),
            MessageType::PairCancel => {
                let env: Envelope<PairCancelPayload> = serde_json::from_str(input)?;
                Ok(Self::PairCancel {
                    reason: env.payload.reason,
                })
            }
            MessageType::ChallengeOk => {
                let env: Envelope<ChallengeOkPayload> = serde_json::from_str(input)?;
                Ok(Self::ChallengeOk(env.payload))
            }
            MessageType::RegisterOk => {
                let env: Envelope<RegisterOkPayload> = serde_json::from_str(input)?;
                Ok(Self::RegisterOk(env.payload))
            }
            MessageType::RegisterError => {
                let env: Envelope<ErrorPayload> = serde_json::from_str(input)?;
                Ok(Self::RegisterError(env.payload))
            }
            MessageType::HelloOk => {
                let env: Envelope<HelloOkPayload> = serde_json::from_str(input)?;
                Ok(Self::HelloOk(env.payload))
            }
            MessageType::HelloError => {
                let env: Envelope<ErrorPayload> = serde_json::from_str(input)?;
                Ok(Self::HelloError(env.payload))
            }
            MessageType::Msg => {
                let env: Envelope<MsgPayload> = serde_json::from_str(input)?;
                Ok(Self::Msg(env.payload))
            }
            MessageType::Pong => Ok(Self::Pong),
            MessageType::PairData => {
                let env: Envelope<PairDataPayload> = serde_json::from_str(input)?;
                let pair_data = match env.payload.t.as_str() {
                    "hello" => PairDataMessage::Hello {
                        salt: env.payload.salt.ok_or(ProtocolError::InvalidPairData)?,
                    },
                    "join" => PairDataMessage::Join {
                        salt: env.payload.salt.ok_or(ProtocolError::InvalidPairData)?,
                    },
                    "proof_b" => PairDataMessage::ProofB {
                        proof: env.payload.proof.ok_or(ProtocolError::InvalidPairData)?,
                    },
                    "grant" => PairDataMessage::Grant {
                        proof: env.payload.proof.ok_or(ProtocolError::InvalidPairData)?,
                        wrapped_key: env
                            .payload
                            .wrapped_key
                            .ok_or(ProtocolError::InvalidPairData)?,
                    },
                    _ => return Err(ProtocolError::InvalidPairData),
                };
                Ok(Self::PairData(pair_data))
            }
            MessageType::PairOpen
            | MessageType::Challenge
            | MessageType::Register
            | MessageType::Hello
            | MessageType::Ping => Err(ProtocolError::UnsupportedMessage),
        }
    }
}

impl InnerMessage {
    pub fn text(text: impl Into<String>) -> Self {
        Self::new(
            InnerMessageType::Text,
            None,
            serde_json::json!({ "text": text.into() }),
        )
    }

    pub fn text_with_sender(text: impl Into<String>, from: SenderInfo) -> Self {
        Self::new(
            InnerMessageType::Text,
            Some(from),
            serde_json::json!({ "text": text.into() }),
        )
    }

    pub fn text_delta(id: Uuid, delta: impl Into<String>, ts: i64) -> Self {
        Self {
            t: InnerMessageType::TextDelta,
            id,
            from: None,
            body: serde_json::json!({ "delta": delta.into() }),
            ts,
        }
    }

    pub fn text_end(id: Uuid, text: impl Into<String>, ts: i64) -> Self {
        Self {
            t: InnerMessageType::TextEnd,
            id,
            from: None,
            body: serde_json::json!({ "text": text.into() }),
            ts,
        }
    }

    pub fn status(status: impl Into<String>) -> Self {
        Self::new(
            InnerMessageType::Status,
            None,
            serde_json::json!({ "status": status.into() }),
        )
    }

    pub fn new(t: InnerMessageType, from: Option<SenderInfo>, body: Value) -> Self {
        Self {
            t,
            id: Uuid::new_v4(),
            from,
            body,
            ts: unix_ms(),
        }
    }
}

fn unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}
