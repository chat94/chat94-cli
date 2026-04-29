// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use chat4000_proto::{
    ChallengeOkPayload, ClientRole, Envelope, IncomingMessage, InnerMessage, InnerMessageType,
    MessageType, PairDataMessage, PairingRole, RelayOutgoing, SenderInfo, SenderRole,
    WrappedGroupKey,
};
use chat4000_proto::{HelloOkPayload, VersionPolicy};
use serde_json::Value;

#[test]
fn hello_builder_produces_expected_fields() {
    let json = RelayOutgoing::hello(
        "abc123",
        Some("token-1".into()),
        Some("com.neonnode.chat4000app.dev".into()),
        Some("1.2.3".into()),
    )
    .unwrap();
    let object: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(object["version"], 1);
    assert_eq!(object["type"], "hello");
    assert_eq!(object["payload"]["role"], "app");
    assert_eq!(object["payload"]["group_id"], "abc123");
    assert_eq!(object["payload"]["device_token"], "token-1");
    assert_eq!(object["payload"]["app_id"], "com.neonnode.chat4000app.dev");
    assert_eq!(object["payload"]["app_version"], "1.2.3");
}

#[test]
fn hello_ok_with_version_policy_parses() {
    let json = r#"{
        "version":1,
        "type":"hello_ok",
        "payload":{
            "current_terms_version":200,
            "version_policy":{
                "min_version":"1.0.0",
                "recommended_version":"1.2.0",
                "latest_version":"1.3.0"
            }
        }
    }"#;
    let parsed = IncomingMessage::parse(json).unwrap();
    let IncomingMessage::HelloOk(payload) = parsed else {
        panic!("expected HelloOk");
    };
    assert_eq!(payload.current_terms_version, Some(200));
    let policy = payload.version_policy.unwrap();
    assert_eq!(policy.min_version.as_deref(), Some("1.0.0"));
    assert_eq!(policy.recommended_version.as_deref(), Some("1.2.0"));
    assert_eq!(policy.latest_version.as_deref(), Some("1.3.0"));
}

#[test]
fn hello_ok_without_version_policy_parses() {
    let json = r#"{"version":1,"type":"hello_ok","payload":{"current_terms_version":200}}"#;
    let parsed = IncomingMessage::parse(json).unwrap();
    let IncomingMessage::HelloOk(payload) = parsed else {
        panic!("expected HelloOk");
    };
    assert!(payload.version_policy.is_none());
    assert_eq!(payload.current_terms_version, Some(200));
}

#[test]
fn hello_ok_with_all_null_policy_fields_parses() {
    let json = r#"{
        "version":1,
        "type":"hello_ok",
        "payload":{
            "version_policy":{
                "min_version":null,
                "recommended_version":null,
                "latest_version":null
            }
        }
    }"#;
    let parsed = IncomingMessage::parse(json).unwrap();
    let IncomingMessage::HelloOk(payload) = parsed else {
        panic!("expected HelloOk");
    };
    let policy = payload.version_policy.unwrap();
    assert_eq!(policy, VersionPolicy::default());
}

#[test]
fn hello_ok_empty_payload_still_parses() {
    let parsed =
        IncomingMessage::parse(r#"{"version":1,"type":"hello_ok","payload":{}}"#).unwrap();
    let IncomingMessage::HelloOk(payload) = parsed else {
        panic!("expected HelloOk");
    };
    assert_eq!(payload, HelloOkPayload::default());
}

#[test]
fn pair_grant_builder_produces_expected_fields() {
    let wrapped = WrappedGroupKey {
        ephemeral_pub: "pub-1".into(),
        nonce: "nonce-1".into(),
        ciphertext: "cipher-1".into(),
    };
    let json = RelayOutgoing::pair_grant("proof-a", wrapped).unwrap();
    let object: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(object["type"], "pair_data");
    assert_eq!(object["payload"]["t"], "grant");
    assert_eq!(object["payload"]["proof"], "proof-a");
    assert_eq!(object["payload"]["wrapped_key"]["ephemeral_pub"], "pub-1");
}

#[test]
fn parses_supported_incoming_messages() {
    let cases = [
        r#"{"version":1,"type":"challenge_ok","payload":{"nonce":"abc","expires_in_secs":60}}"#,
        r#"{"version":1,"type":"register_ok","payload":{"group_id":"group-id"}}"#,
        r#"{"version":1,"type":"register_error","payload":{"code":"NOPE","message":"failed"}}"#,
        r#"{"version":1,"type":"hello_ok","payload":{}}"#,
        r#"{"version":1,"type":"hello_error","payload":{"code":"NOPE","message":"failed"}}"#,
        r#"{"version":1,"type":"msg","payload":{"nonce":"n","ciphertext":"c","msg_id":"m"}}"#,
        r#"{"version":1,"type":"pong","payload":null}"#,
        r#"{"version":1,"type":"pair_open_ok","payload":{}}"#,
        r#"{"version":1,"type":"pair_ready","payload":{}}"#,
        r#"{"version":1,"type":"pair_data","payload":{"t":"hello","salt":"a"}}"#,
        r#"{"version":1,"type":"pair_data","payload":{"t":"join","salt":"b"}}"#,
        r#"{"version":1,"type":"pair_data","payload":{"t":"proof_b","proof":"c"}}"#,
        r#"{"version":1,"type":"pair_data","payload":{"t":"grant","proof":"d","wrapped_key":{"ephemeral_pub":"e1","nonce":"e2","ciphertext":"e3"}}}"#,
        r#"{"version":1,"type":"pair_complete","payload":{"status":"ok"}}"#,
        r#"{"version":1,"type":"pair_cancel","payload":{}}"#,
    ];

    for json in cases {
        assert!(
            IncomingMessage::parse(json).is_ok(),
            "failed parsing {json}"
        );
    }
}

#[test]
fn unsupported_incoming_type_returns_error() {
    let json = r#"{"version":1,"type":"hello","payload":{"role":"app","group_id":"x"}}"#;
    assert!(IncomingMessage::parse(json).is_err());
}

#[test]
fn relay_level_typing_messages_are_unsupported() {
    assert!(IncomingMessage::parse(r#"{"version":1,"type":"typing","payload":{}}"#).is_err());
    assert!(IncomingMessage::parse(r#"{"version":1,"type":"typing_stop","payload":{}}"#).is_err());
}

#[test]
fn inner_message_serializes_with_expected_shape() {
    let inner = InnerMessage::text_with_sender(
        "hello",
        SenderInfo {
            role: SenderRole::App,
            device_id: "device-1".into(),
            device_name: "Terminal".into(),
            app_version: Some("1.0.3".into()),
            bundle_id: Some("com.neonnode.chat4000app".into()),
        },
    );
    let value = serde_json::to_value(inner).unwrap();
    assert_eq!(value["t"], "text");
    assert_eq!(value["body"]["text"], "hello");
    assert_eq!(value["from"]["role"], "app");
    assert_eq!(value["from"]["device_id"], "device-1");
    assert_eq!(value["from"]["device_name"], "Terminal");
    assert_eq!(value["from"]["app_version"], "1.0.3");
    assert_eq!(value["from"]["bundle_id"], "com.neonnode.chat4000app");
    assert!(value["id"].as_str().is_some());
}

#[test]
fn inner_message_accepts_missing_sender_metadata() {
    let json = r#"{
        "t":"text",
        "id":"00000000-0000-0000-0000-000000000001",
        "from":{"role":"plugin","device_id":"plugin-1","device_name":"OpenClaw chat4000"},
        "body":{"text":"hello"},
        "ts":1710000000000
    }"#;

    let inner: InnerMessage = serde_json::from_str(json).unwrap();
    let sender = inner.from.unwrap();

    assert_eq!(sender.role, SenderRole::Plugin);
    assert_eq!(sender.device_id, "plugin-1");
    assert_eq!(sender.device_name, "OpenClaw chat4000");
    assert_eq!(sender.app_version, None);
    assert_eq!(sender.bundle_id, None);
}

#[test]
fn envelope_roundtrip_and_type_serde() {
    let env = Envelope::new(
        MessageType::Hello,
        serde_json::json!({
            "role": "app",
            "group_id": "abc",
            "device_token": null,
            "app_id": null
        }),
    );
    let json = serde_json::to_string(&env).unwrap();
    let parsed: Envelope<Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.msg_type, MessageType::Hello);

    let payload = serde_json::to_string(&ChallengeOkPayload {
        nonce: "abc".into(),
        expires_in_secs: 60,
    })
    .unwrap();
    assert_eq!(payload, r#"{"nonce":"abc","expires_in_secs":60}"#);

    let role_json = serde_json::to_string(&ClientRole::App).unwrap();
    assert_eq!(role_json, "\"app\"");
    let pair_role_json = serde_json::to_string(&PairingRole::Joiner).unwrap();
    assert_eq!(pair_role_json, "\"joiner\"");
    let sender_role_json = serde_json::to_string(&SenderRole::Plugin).unwrap();
    assert_eq!(sender_role_json, "\"plugin\"");
}

#[test]
fn pair_data_parse_maps_to_variants() {
    let hello = IncomingMessage::parse(
        r#"{"version":1,"type":"pair_data","payload":{"t":"hello","salt":"a"}}"#,
    )
    .unwrap();
    assert!(
        matches!(hello, IncomingMessage::PairData(PairDataMessage::Hello { salt }) if salt == "a")
    );

    let grant = IncomingMessage::parse(
        r#"{"version":1,"type":"pair_data","payload":{"t":"grant","proof":"p","wrapped_key":{"ephemeral_pub":"e1","nonce":"e2","ciphertext":"e3"}}}"#,
    )
    .unwrap();
    assert!(
        matches!(grant, IncomingMessage::PairData(PairDataMessage::Grant { proof, .. }) if proof == "p")
    );
}

#[test]
fn inner_message_type_serde_matches_snake_case() {
    let json = serde_json::to_string(&InnerMessageType::TextDelta).unwrap();
    assert_eq!(json, "\"text_delta\"");
    let audio_json = serde_json::to_string(&InnerMessageType::Audio).unwrap();
    assert_eq!(audio_json, "\"audio\"");
}
