// chat94
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use rand::distr::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const GROUP_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const PAIR_WRAP_INFO: &[u8] = b"chat94-pair-wrap-v1";
pub const PAIRING_ROOM_PREFIX: &[u8] = b"pairing-v1:";
pub const PAIRING_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPRTUVWXYZ2346789";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedGroupKey {
    pub ephemeral_pub: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinerKeypair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("expected 32-byte key")]
    InvalidKeyLength,
    #[error("invalid base64 data")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid x25519 public key")]
    InvalidPublicKey,
    #[error("invalid nonce length")]
    InvalidNonceLength,
}

pub fn derive_group_id(group_key: &[u8]) -> String {
    hex_lower(Sha256::digest(group_key).as_slice())
}

pub fn generate_group_key() -> [u8; GROUP_KEY_LEN] {
    let mut key = [0u8; GROUP_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn normalize_pairing_code(input: &str) -> String {
    input
        .trim()
        .chars()
        .flat_map(char::to_uppercase)
        .filter(|ch| PAIRING_CODE_ALPHABET.contains(&(*ch as u8)))
        .collect()
}

pub fn generate_pairing_code() -> String {
    let mut rng = rand::rng();
    let dist = Uniform::new(0, PAIRING_CODE_ALPHABET.len()).expect("valid uniform range");
    let chars: Vec<char> = (0..8)
        .map(|_| PAIRING_CODE_ALPHABET[dist.sample(&mut rng)] as char)
        .collect();
    format!(
        "{}{}{}{}-{}{}{}{}",
        chars[0], chars[1], chars[2], chars[3], chars[4], chars[5], chars[6], chars[7]
    )
}

pub fn derive_pairing_room_id(code: &str) -> String {
    let normalized = normalize_pairing_code(code);
    let mut hasher = Sha256::new();
    hasher.update(PAIRING_ROOM_PREFIX);
    hasher.update(normalized.as_bytes());
    hex_lower(hasher.finalize().as_slice())
}

pub fn derive_pair_proof(
    code: &str,
    initiator_salt: &[u8],
    joiner_public_key: &[u8],
    label: &str,
) -> String {
    let normalized = normalize_pairing_code(code);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.update([0]);
    hasher.update(initiator_salt);
    hasher.update([0]);
    hasher.update(joiner_public_key);
    hasher.update([0]);
    hasher.update(label.as_bytes());
    STANDARD.encode(hasher.finalize())
}

pub fn generate_joiner_keypair() -> JoinerKeypair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    JoinerKeypair {
        private_key: private.to_bytes(),
        public_key: public.to_bytes(),
    }
}

pub fn wrap_group_key(
    group_key: &[u8],
    joiner_public_key: &[u8],
) -> Result<WrappedGroupKey, CryptoError> {
    if group_key.len() != GROUP_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    let public_key = bytes_to_public_key(joiner_public_key)?;
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let shared_secret = ephemeral.diffie_hellman(&public_key);
    let wrap_key = derive_wrap_key(shared_secret.as_bytes());
    let encrypted = encrypt(group_key, &wrap_key)?;
    Ok(WrappedGroupKey {
        ephemeral_pub: STANDARD.encode(PublicKey::from(&ephemeral).to_bytes()),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

pub fn unwrap_group_key(
    wrapped: &WrappedGroupKey,
    joiner_private_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let sender_public_raw = STANDARD.decode(&wrapped.ephemeral_pub)?;
    let sender_public_key = bytes_to_public_key(&sender_public_raw)?;
    let private_key = bytes_to_static_secret(joiner_private_key)?;
    let shared_secret = private_key.diffie_hellman(&sender_public_key);
    let wrap_key = derive_wrap_key(shared_secret.as_bytes());
    let plaintext = decrypt(&wrapped.nonce, &wrapped.ciphertext, &wrap_key)?;
    if plaintext.len() != GROUP_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(plaintext)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<EncryptedMessage, CryptoError> {
    if key.len() != GROUP_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(EncryptedMessage {
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt(nonce_b64: &str, ciphertext_b64: &str, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != GROUP_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    let nonce = STANDARD.decode(nonce_b64)?;
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength);
    }
    let ciphertext = STANDARD.decode(ciphertext_b64)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn derive_wrap_key(shared_secret: &[u8]) -> [u8; GROUP_KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(PAIR_WRAP_INFO);
    hasher.finalize().into()
}

fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    Ok(PublicKey::from(array))
}

fn bytes_to_static_secret(bytes: &[u8]) -> Result<StaticSecret, CryptoError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(StaticSecret::from(array))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
