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
        "device-xyz",
        Some("token-1".into()),
        Some("com.neonnode.chat4000app.dev".into()),
        Some("1.2.3".into()),
        Some("dev".into()),
        Some(4123),
    )
    .unwrap();
    let object: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(object["version"], 1);
    assert_eq!(object["type"], "hello");
    assert_eq!(object["payload"]["role"], "app");
    assert_eq!(object["payload"]["group_id"], "abc123");
    assert_eq!(object["payload"]["device_id"], "device-xyz");
    assert_eq!(object["payload"]["device_token"], "token-1");
    assert_eq!(object["payload"]["app_id"], "com.neonnode.chat4000app.dev");
    assert_eq!(object["payload"]["app_version"], "1.2.3");
    assert_eq!(object["payload"]["release_channel"], "dev");
    assert_eq!(object["payload"]["last_acked_seq"], 4123);
}

#[test]
fn hello_omits_last_acked_seq_when_unset() {
    let json = RelayOutgoing::hello("g", "d", None, None, None, None, None).unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();
    assert!(value["payload"].get("last_acked_seq").is_none());
    assert!(value["payload"].get("release_channel").is_none());
}

#[test]
fn recv_ack_builder_round_trip() {
    let json = RelayOutgoing::recv_ack(4180, vec![[4182, 4191]]).unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["type"], "recv_ack");
    assert_eq!(value["payload"]["up_to_seq"], 4180);
    assert_eq!(value["payload"]["ranges"][0][0], 4182);
    assert_eq!(value["payload"]["ranges"][0][1], 4191);
}

#[test]
fn relay_recv_ack_parses() {
    let json = r#"{"version":1,"type":"relay_recv_ack","payload":{"msg_id":"m-1","queued_for":["plugin"]}}"#;
    let parsed = IncomingMessage::parse(json).unwrap();
    let IncomingMessage::RelayRecvAck(payload) = parsed else {
        panic!("expected RelayRecvAck");
    };
    assert_eq!(payload.msg_id, "m-1");
    assert_eq!(payload.queued_for, vec!["plugin".to_string()]);
}

#[test]
fn msg_with_seq_parses() {
    let json = r#"{"version":1,"type":"msg","payload":{"nonce":"n","ciphertext":"c","msg_id":"m","seq":4124,"notify_if_offline":true}}"#;
    let parsed = IncomingMessage::parse(json).unwrap();
    let IncomingMessage::Msg(payload) = parsed else {
        panic!("expected Msg");
    };
    assert_eq!(payload.seq, Some(4124));
    assert_eq!(payload.notify_if_offline, Some(true));
}

#[test]
fn inner_ack_round_trip() {
    let sender = SenderInfo {
        role: SenderRole::App,
        device_id: "d-1".into(),
        device_name: "CLI".into(),
        app_version: Some("1.0.1".into()),
        bundle_id: Some("com.neonnode.chat4000cli".into()),
    };
    let inner = InnerMessage::ack_received("msg-uuid-1", sender);
    let serialized = serde_json::to_string(&inner).unwrap();
    let round_trip: InnerMessage = serde_json::from_str(&serialized).unwrap();
    let ack = round_trip.as_ack().unwrap();
    assert_eq!(ack.refs, "msg-uuid-1");
    assert_eq!(ack.stage, "received");
    assert_eq!(round_trip.t, InnerMessageType::Ack);
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
    let parsed = IncomingMessage::parse(r#"{"version":1,"type":"hello_ok","payload":{}}"#).unwrap();
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
