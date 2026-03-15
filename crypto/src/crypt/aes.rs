//! AES-256-GCM symmetric encryption.
//!
//! Used to encrypt the actual password strings stored in the vault.
//! Each vault entry gets its own unique 32-byte session key; see
//! `session_key` for how that key is itself protected.
//!
//! # Blob format
//! Every function in this module that returns `Vec<u8>` uses the layout:
//! ```text
//! [ nonce (12 bytes) ][ ciphertext (n bytes) ][ GCM auth tag (16 bytes) ]
//! ```
//! The nonce is randomly generated and prepended so the blob is self-contained.
//! The GCM tag provides authenticated encryption — any tampering or wrong key
//! returns `Err` immediately on decryption.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key, Nonce,
};

/// Generates a cryptographically random 32-byte AES-256 session key.
///
/// **One key per vault entry.** Reusing a key with AES-GCM across multiple
/// encryptions risks nonce collision which breaks confidentiality entirely.
///
/// # Returns
/// `[u8; 32]` — 256-bit key suitable for AES-256-GCM
pub fn generate_aes_session_key() -> [u8; 32] {
    Aes256Gcm::generate_key(&mut AesOsRng).into()
}

/// Encrypts a UTF-8 plaintext string under AES-256-GCM.
///
/// A fresh 96-bit nonce is generated and prepended to the output so the
/// blob is fully self-contained for storage.
///
/// # Arguments
/// * `plaintext`   — The password / secret string to encrypt
/// * `session_key` — 32-byte key from [`generate_aes_session_key`]
///
/// # Returns
/// * `Ok(Vec<u8>)` — `nonce(12) ++ ciphertext(n) ++ tag(16)`
/// * `Err(String)` — AES-GCM error (should never occur for valid key sizes)
pub fn encrypt_string_with_aes(
    plaintext: &str,
    session_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    // A fresh 96-bit nonce must be used every call with the same key
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

    // Prepend nonce so decryption is self-contained (no separate nonce storage)
    let mut blob = nonce.to_vec();       // 12 bytes
    blob.extend_from_slice(&ciphertext); // n bytes ciphertext + 16-byte GCM tag
    Ok(blob)
}

/// Decrypts an AES-256-GCM blob produced by [`encrypt_string_with_aes`].
///
/// The GCM auth tag is verified before any plaintext is returned. A wrong
/// key, a tampered ciphertext, or a truncated blob all return `Err`.
///
/// # Arguments
/// * `blob`        — `nonce(12) ++ ciphertext(n) ++ tag(16)` from `encrypt_string_with_aes`
/// * `session_key` — The same 32-byte key used during encryption
///
/// # Returns
/// * `Ok(String)`  — Recovered UTF-8 plaintext
/// * `Err(String)` — Auth failure, wrong key, short blob, or invalid UTF-8
pub fn decrypt_string_with_aes(
    blob: &[u8],
    session_key: &[u8; 32],
) -> Result<String, String> {
    // Minimum valid blob: 12-byte nonce + 16-byte GCM tag (zero-length plaintext)
    if blob.len() < 28 {
        return Err(format!(
            "Blob too short: {} bytes (minimum 28 = 12 nonce + 16 tag)",
            blob.len()
        ));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decryption failed (wrong key or tampered data): {e}"))?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted bytes are not valid UTF-8: {e}"))
}


// FILE ENCRYPTION AND DECRYPTION
pub fn encrypt_bytes_with_aes(
    plaintext: &[u8],
    session_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

pub fn decrypt_bytes_with_aes(
    blob: &[u8],
    session_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // Minimum valid blob: 12-byte nonce + 16-byte tag
    if blob.len() < 28 {
        return Err(format!(
            "Blob too short: {} bytes (minimum 28 = 12 nonce + 16 tag)",
            blob.len()
        ));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decryption failed (wrong key or tampered data): {e}"))?;

    Ok(plaintext)
}