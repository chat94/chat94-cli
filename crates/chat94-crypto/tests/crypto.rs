// chat94
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use chat94_crypto::{
    decrypt, derive_group_id, derive_pair_proof, derive_pairing_room_id, encrypt,
    generate_group_key, generate_joiner_keypair, generate_pairing_code, normalize_pairing_code,
    unwrap_group_key, wrap_group_key,
};

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = [0x11; 32];
    let plaintext = b"hello from Chat94";
    let encrypted = encrypt(plaintext, &key).unwrap();
    let decrypted = decrypt(&encrypted.nonce, &encrypted.ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_key_fails_to_decrypt() {
    let key = [0x11; 32];
    let wrong_key = [0x22; 32];
    let encrypted = encrypt(b"secret", &key).unwrap();
    assert!(decrypt(&encrypted.nonce, &encrypted.ciphertext, &wrong_key).is_err());
}

#[test]
fn derive_group_id_produces_consistent_sha256_hex() {
    let k1 = [0x33; 32];
    let k2 = [0x33; 32];
    let k3 = [0x44; 32];
    assert_eq!(derive_group_id(&k1), derive_group_id(&k2));
    assert_ne!(derive_group_id(&k1), derive_group_id(&k3));
    assert_eq!(derive_group_id(&k1).len(), 64);
}

#[test]
fn generate_group_key_returns_32_bytes() {
    assert_eq!(generate_group_key().len(), 32);
}

#[test]
fn normalizes_pairing_codes_and_derives_room_ids() {
    assert_eq!(normalize_pairing_code("abCd-2346"), "ABCD2346");
    assert_eq!(
        derive_pairing_room_id("ABCD-2346"),
        derive_pairing_room_id("abcd2346")
    );
}

#[test]
fn generates_pairing_codes_in_expected_format() {
    let code = generate_pairing_code();
    assert!(code.len() == 9);
    assert_eq!(code.chars().nth(4), Some('-'));
    assert!(!code.contains(['0', '1', 'I', 'L', 'O', 'S', '5']));
}

#[test]
fn computes_pairing_proof_using_exact_spec_separators() {
    let proof = derive_pair_proof("ABCD2346", b"salt-value", &[0x23; 32], "B");
    assert_eq!(proof, "iqH42fMsdUtAwURmEZj1m2GlqS3itz12RWHDLARn7aE=");
}

#[test]
fn wraps_and_unwraps_group_key_via_x25519_and_xchacha20poly1305() {
    let group_key = [0x11; 32];
    let keypair = generate_joiner_keypair();
    let wrapped = wrap_group_key(&group_key, &keypair.public_key).unwrap();
    let unwrapped = unwrap_group_key(&wrapped, &keypair.private_key).unwrap();
    assert_eq!(unwrapped, group_key);
}
