//! PGP key operations.
//!
//! Responsibilities:
//! - Generate Ed25519 PGP keypairs protected by a master password via S2K
//! - Extract a usable X25519 private key from an ASCII-armored PGP private key
//! - Decrypt ECIES blobs using the derived X25519 private key
//!
//! # Key derivation path
//! ASCII-armored private key
//!   → S2K unlock (AES-256-CFB via SHA-256, GPG-compatible)
//!   → Ed25519 seed bytes (32)
//!   → SHA-512 hash → first 32 bytes → clamped X25519 scalar
//!
//! # ECIES blob layout
//! [ ephemeral_pubkey (32) | nonce (12) | ciphertext+tag (...) ]

use pgp::composed::{
    ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey,
};
use pgp::types::{Password, PlainSecretParams};
use rand::thread_rng;
use sha2::{Digest, Sha256, Sha512};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
use pgp::types::{EddsaLegacyPublicParams, PublicParams};
use pgp::types::Ed25519PublicParams;
use ed25519_dalek::VerifyingKey;
use pgp::types::{PublicKeyTrait};
// ─── Key Generation ──────────────────────────────────────────────────────────

/// Generates a fresh Ed25519 PGP keypair.
///
/// The private key is S2K-protected (iterated+salted SHA-256 → AES-256-CFB)
/// using `mpass` at the packet level. The returned `secret_key_asc` string
/// is encrypted at rest and cannot be used without `mpass`.
///
/// # Returns
/// `(public_key_asc, secret_key_asc)` — both ASCII-armored.
pub fn generate_key_pairs(
    mpass: &str,
    user_id: &str, // e.g. "Alice <alice@example.com>"
) -> Result<(String, String), String> {
    let mut rng = thread_rng();

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .can_certify(true)
        .can_authenticate(true)
        .primary_user_id(user_id.into())
        .passphrase(Some(mpass.into()))
        .build()
        .map_err(|e| format!("Failed to build key params: {e}"))?;

    let secret_key = params
        .generate(&mut rng)
        .map_err(|e| format!("Failed to generate secret key: {e}"))?;

    let password = Password::from(mpass);

    let signed_secret_key: SignedSecretKey = secret_key
        .sign(&mut rng, &password)
        .map_err(|e| format!("Failed to sign secret key: {e}"))?;

    let signed_public_key: SignedPublicKey = signed_secret_key.signed_public_key();

    let secret_key_asc = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format!("Failed to armor secret key: {e}"))?;

    let public_key_asc = signed_public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format!("Failed to armor public key: {e}"))?;

    Ok((public_key_asc, secret_key_asc))
}

// ─── Key Extraction ───────────────────────────────────────────────────────────

/// Unlocks an ASCII-armored PGP private key and derives a usable X25519 scalar.
///
/// Ed25519 and X25519 both use Curve25519 but in different representations.
/// We derive the X25519 scalar via the RFC 8037 / libsodium convention:
/// `SHA-512(ed25519_seed)[0..32]`, then clamped per the X25519 spec.
///
/// # Arguments
/// * `private_key_asc` — ASCII-armored, S2K-protected PGP private key
/// * `mpass`           — Master password used when the key was generated
///
/// # Returns
/// 32-byte X25519 private scalar, ready for DH operations.
pub fn private_key_asc_to_x25519_bytes(
    private_key_asc: &str,
    mpass: &str,
) -> Result<[u8; 32], String> {
    let (signed_secret, _) = SignedSecretKey::from_string(private_key_asc)
        .map_err(|e| format!("Failed to parse private key: {e}"))?;

    signed_secret
        .verify()
        .map_err(|e| format!("Key self-signature invalid: {e}"))?;

    // Build password callback required by the pgp crate
    let pass = mpass.to_string();
    let password = Password::from(move || Zeroizing::new(pass.as_bytes().to_vec()));

    // Unlock and extract the raw Ed25519 seed (32 bytes)
    let ed25519_seed: Vec<u8> = signed_secret
        .primary_key
        .unlock(&password, |_public, secret| match secret {
            PlainSecretParams::Ed25519(s) | PlainSecretParams::Ed25519Legacy(s) => {
                Ok(s.to_bytes().to_vec())
            }
            _ => Err("Primary key is not Ed25519".to_string().into()),
        })
        .map_err(|_| "Wrong master password (S2K unlock failed)".to_string())?
        .map_err(|e| format!("Failed to extract Ed25519 seed: {e}"))?;

    if ed25519_seed.len() != 32 {
        return Err(format!(
            "Unexpected Ed25519 seed length: {} (expected 32)",
            ed25519_seed.len()
        ));
    }

    // Derive X25519 scalar: SHA-512(seed), take low 32 bytes, clamp
    let hash = Sha512::digest(&ed25519_seed);
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&hash[..32]);

    // Clamp per RFC 7748 §5
    x25519[0] &= 248;
    x25519[31] &= 127;
    x25519[31] |= 64;

    Ok(x25519)
}

pub fn public_key_asc_to_x25519_bytes(public_key_asc: &str) -> Result<[u8; 32], String> {
    let (signed_public, _) = SignedPublicKey::from_string(public_key_asc)
        .map_err(|e| format!("Failed to parse public key: {e}"))?;

    let key: &VerifyingKey = match signed_public.primary_key.public_params() {
        PublicParams::Ed25519(params) => &params.key,

        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => &key,

        _ => return Err("Primary key is not Ed25519".to_string()),
    };

    Ok(key.to_montgomery().to_bytes())
}
// ─── Decryption ───────────────────────────────────────────────────────────────

/// Decrypts an ECIES blob using an X25519 private key.
///
/// # Blob layout
/// ```text
/// [ ephemeral_pubkey (32) | nonce (12) | AES-256-GCM ciphertext+tag ]
/// ```
///
/// The AES-256 key is derived as `SHA-256(X25519_shared_secret)`.
///
/// # Arguments
/// * `private_key` — 32-byte X25519 scalar (from `private_key_asc_to_x25519_bytes`)
/// * `blob`        — Raw encrypted blob
///
/// # Returns
/// Decrypted plaintext bytes, or an error if the key is wrong or the blob is malformed.
pub fn decrypt_with_x25519_private_key(
    private_key: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    const EPHEM_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    const MIN_BLOB: usize = EPHEM_LEN + NONCE_LEN + TAG_LEN;

    if blob.len() < MIN_BLOB {
        return Err(format!(
            "Blob too short: {} bytes (minimum {MIN_BLOB})",
            blob.len()
        ));
    }

    let ephemeral_pubkey_bytes: [u8; 32] = blob[0..32]
        .try_into()
        .map_err(|_| "Invalid ephemeral public key slice")?;

    let nonce_bytes: [u8; 12] = blob[32..44]
        .try_into()
        .map_err(|_| "Invalid nonce slice")?;

    let ciphertext = &blob[44..];

    // X25519 ECDH
    let secret = StaticSecret::from(*private_key);
    let ephemeral_pubkey = PublicKey::from(ephemeral_pubkey_bytes);
    let shared_secret = secret.diffie_hellman(&ephemeral_pubkey);

    // KDF: SHA-256(shared_secret) → AES-256 key
    let aes_key = Sha256::digest(shared_secret.as_bytes());

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("ECIES decrypt failed (wrong key or corrupted blob): {e}"))
}

// ─── Convenience ─────────────────────────────────────────────────────────────

/// One-shot: unlock PGP private key from ASC and decrypt an ECIES blob.
///
/// Equivalent to calling `private_key_asc_to_x25519_bytes` then
/// `decrypt_with_x25519_private_key`.
pub fn decrypt_blob_with_asc_key(
    private_key_asc: &str,
    mpass: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    let x25519_key = private_key_asc_to_x25519_bytes(private_key_asc, mpass)?;
    decrypt_with_x25519_private_key(&x25519_key, blob)
}

pub fn public_key_asc_to_x25519_bytess(
    private_key_asc: &str,
    mpass: &str,
) -> Result<[u8; 32], String> {
    let x25519_private = private_key_asc_to_x25519_bytes(private_key_asc, mpass)?;
    let secret = StaticSecret::from(x25519_private);
    Ok(PublicKey::from(&secret).to_bytes())
}