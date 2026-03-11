//! Session-key protection using X25519 ECIES.
//!
//! Each vault entry has a unique AES-256 session key (see [`crate::crypt::aes`]).
//! That key must be stored securely alongside the ciphertext so only the holder
//! of the correct private key can recover it.
//!
//! # Why X25519 ECIES instead of PGP PKESK?
//! The pgp crate's message-level encryption API (`encrypt_to_keys`,
//! `encrypt_to_keys_seipdv1`, etc.) has never been stable in any 0.x release —
//! method names change or disappear every minor version, and internal types
//! (`LiteralDataReader`, `MessageReader`) are not publicly constructable.
//!
//! X25519 ECIES is cryptographically identical to what OpenPGP does internally
//! for ECDH keys, and uses crates with permanently stable public APIs.
//!
//! # Blob wire format
//! ```text
//! encrypt_session_key_with_public_key output (92 bytes total):
//!   ephemeral_public_key  [32 bytes]  — fresh X25519 pubkey, unique per call
//!   nonce                 [12 bytes]  — AES-GCM nonce
//!   ciphertext + tag      [48 bytes]  — AES-256-GCM encrypted 32-byte session key
//! ```
//!
//! # Key management
//! ```text
//! generate_x25519_keypair() → (private[32], public[32])
//!   public  → store in vault metadata (plaintext)
//!   private → protect with encrypt_x25519_private_key_with_mpass()
//!             blob format: salt(16) ++ nonce(12) ++ ciphertext(32) ++ tag(16) = 76 bytes
//! ```

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};

// ── X25519 keypair ─────────────────────────────────────────────────────────────

/// Generates a fresh X25519 keypair for the asymmetric layer.
///
/// Returns `(private_key[32], public_key[32])`.
/// - **public key**  → store in vault metadata (plaintext is fine)
/// - **private key** → must be protected via [`encrypt_x25519_private_key_with_mpass`]
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519Public::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

// ── X25519 private key protect / unprotect ────────────────────────────────────

/// Protects the 32-byte X25519 private key under the master password.
///
/// KDF: Argon2id (m=64 MB, t=3, p=1) → 32-byte wrapping key → AES-256-GCM.
///
/// Blob format: `salt(16) ++ nonce(12) ++ ciphertext(32) ++ tag(16)` = **76 bytes**
pub fn encrypt_x25519_private_key_with_mpass(
    mpass: &str,
    private_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let wrapping_key = argon2id_kdf(mpass, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, private_key.as_slice())
        .map_err(|e| format!("AES-GCM encrypt failed: {e}"))?;

    let mut blob = Vec::with_capacity(76);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Recovers the X25519 private key from its master-password-protected blob.
///
/// Blob format: `salt(16) ++ nonce(12) ++ ciphertext+tag(48)` = **76 bytes**
pub fn decrypt_x25519_private_key_with_mpass(
    mpass: &str,
    blob: &[u8],
) -> Result<[u8; 32], String> {
    if blob.len() < 76 {
        return Err(format!("Blob too short: {} bytes (expected 76)", blob.len()));
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let wrapping_key = argon2id_kdf(mpass, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decrypt failed (wrong password?): {e}"))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ── session key encrypt / decrypt (ECIES) ─────────────────────────────────────

/// Encrypts the 32-byte AES session key to the recipient's X25519 public key
/// using ECIES: ephemeral ECDH → HKDF-SHA256 → AES-256-GCM.
///
/// A fresh ephemeral keypair is generated per call (forward secrecy).
///
/// Blob format: `eph_pub(32) ++ nonce(12) ++ ciphertext(32) ++ tag(16)` = **92 bytes**
pub fn encrypt_session_key_with_public_key(
    session_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let recipient_pub = X25519Public::from(*recipient_public_key);
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    // ECDH → HKDF → 32-byte wrapping key
    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);
    let wrapping_key = hkdf_sha256(shared.as_bytes(), b"session-key-wrap")?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

    let ciphertext = cipher
        .encrypt(&nonce, session_key.as_slice())
        .map_err(|e| format!("ECIES encrypt failed: {e}"))?;

    let mut blob = Vec::with_capacity(92);
    blob.extend_from_slice(ephemeral_public.as_bytes()); // 32
    blob.extend_from_slice(&nonce);                      // 12
    blob.extend_from_slice(&ciphertext);                 // 32 + 16 tag
    Ok(blob)
}

/// Recovers the 32-byte AES session key from an ECIES blob.
///
/// Blob format: `eph_pub(32) ++ nonce(12) ++ ciphertext+tag(48)` = **92 bytes**
pub fn decrypt_session_key_with_private_key(
    blob: &[u8],
    private_key_bytes: &[u8; 32],
) -> Result<[u8; 32], String> {
    if blob.len() < 92 {
        return Err(format!("Blob too short: {} bytes (expected 92)", blob.len()));
    }
    let (eph_pub_bytes, rest) = blob.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(eph_pub_bytes);
    let ephemeral_pub = X25519Public::from(eph_arr);
    let static_secret = StaticSecret::from(*private_key_bytes);

    // Mirror the encrypt-side ECDH + HKDF
    let shared = static_secret.diffie_hellman(&ephemeral_pub);
    let wrapping_key = hkdf_sha256(shared.as_bytes(), b"session-key-wrap")?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("ECIES decrypt failed (wrong key?): {e}"))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ── private helpers ────────────────────────────────────────────────────────────

/// Argon2id KDF: password + salt → 32-byte output key.
/// Parameters: m=65536 (64 MB), t=3 iterations, p=1 lane.
fn argon2id_kdf(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Argon2, Params, Version};
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| format!("Argon2 params error: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 KDF failed: {e}"))?;
    Ok(key)
}

/// HKDF-SHA256: input key material + info label → 32-byte output key.
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;
    Ok(okm)
}