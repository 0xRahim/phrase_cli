//! PGP key operations.
//!
//! Responsibilities:
//! - Generate Ed25519 PGP keypairs
//! - Re-generate a key protected by a master password via S2K (String-to-Key)
//! - Parse and verify an S2K-protected private key (validates master password)
//!
//! # Why S2K instead of a separate KDF step?
//! The `pgp` crate applies GPG-compatible iterated+salted S2K
//! (SHA-256 → AES-256-CFB) at key-generation time when
//! `SecretKeyParamsBuilder::passphrase(Some(...))` is set.
//! This is the same mechanism used by GnuPG when you export a passphrase-
//! protected private key, so the output is fully interoperable.

use pgp::composed::{
    ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey,
};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Password};
use rand::thread_rng;

/// Generates a fresh Ed25519 PGP keypair and prints both keys as ASCII armor.
///
/// The private key is protected with a hard-coded demonstration passphrase.
/// In production, replace the passphrase with one supplied by the user.
pub fn generate_key_pairs() {
    let mut rng = thread_rng();

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .can_certify(true)
        .can_authenticate(true)
        .primary_user_id("User <user@example.com>".into())
        .passphrase(Some("your-secure-passphrase".into()))
        .build()
        .expect("Failed to build key params");

    let secret_key = params
        .generate(&mut rng)
        .expect("Failed to generate secret key");

    let passphrase = Password::from("your-secure-passphrase");
    let signed_secret_key: SignedSecretKey = secret_key
        .sign(&mut rng, &passphrase)
        .expect("Failed to sign secret key");

    let signed_public_key: SignedPublicKey = signed_secret_key.signed_public_key();

    let fingerprint = signed_public_key
        .fingerprint()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();

    let secret_key_asc = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .expect("Failed to armor secret key");

    let public_key_asc = signed_public_key
        .to_armored_string(ArmorOptions::default())
        .expect("Failed to armor public key");

    println!("=== KEY INFO ===");
    println!("Key ID:      {:?}", signed_public_key.key_id());
    println!("Fingerprint: {fingerprint}");
    println!("\n=== SECRET KEY ===\n{secret_key_asc}");
    println!("=== PUBLIC KEY ===\n{public_key_asc}");
}

/// Re-generates an Ed25519 PGP private key protected by `mpass` using S2K.
///
/// The user ID is extracted from the existing `secret_key_asc` so the new key
/// is logically associated with the same identity. The actual key material is
/// freshly generated — this is not a re-encryption of the original material,
/// because the `pgp` crate only exposes S2K protection at generation time.
///
/// # Arguments
/// * `mpass`          — Master password to protect the key
/// * `secret_key_asc` — Existing ASCII-armored PGP private key (only user ID is read)
///
/// # Returns
/// * `Ok(String)` — ASCII-armored S2K-protected private key
/// * `Err(String)` — Parse or generation failure
pub fn encrypt_private_key(mpass: &str, secret_key_asc: &str) -> Result<String, String> {
    // Parse only to extract the primary user ID
    let (existing_key, _) = SignedSecretKey::from_string(secret_key_asc)
        .map_err(|e| format!("Failed to parse secret key: {e}"))?;

    existing_key
        .verify()
        .map_err(|e| format!("Key verification failed: {e}"))?;

    let user_id = existing_key
        .details
        .users
        .first()
        .map(|u| std::str::from_utf8(u.id.id()).unwrap_or("User <user@example.com>").to_string())
        .unwrap_or_else(|| "User <user@example.com>".to_string());

    // Build params with S2K passphrase — pgp applies iterated+salted SHA-256 → AES-256-CFB
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .can_certify(true)
        .can_authenticate(true)
        .primary_user_id(user_id.into())
        .passphrase(Some(mpass.into()))
        .build()
        .map_err(|e| format!("Failed to build key params: {e}"))?;

    let mut rng = thread_rng();
    let password = Password::from(mpass);

    let new_secret_key = params
        .generate(&mut rng)
        .map_err(|e| format!("Failed to generate key: {e}"))?;

    let signed_secret_key = new_secret_key
        .sign(&mut rng, &password)
        .map_err(|e| format!("Failed to sign key: {e}"))?;

    signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format!("Failed to armor key: {e}"))
}

/// Parses, verifies, and eagerly validates an S2K-protected PGP private key.
///
/// The S2K unlock is attempted immediately so that a wrong master password
/// is caught here rather than silently failing later in
/// `decrypt_session_key_with_private_key`.
///
/// # Arguments
/// * `mpass`          — Master password used when the key was S2K-protected
/// * `secret_key_asc` — ASCII-armored PGP private key
///
/// # Returns
/// * `Ok(SignedSecretKey)` — Parsed and verified key (secret material still
///                           encrypted; `mpass` must be supplied again at
///                           decrypt time per the pgp crate's API)
/// * `Err(String)` — Wrong password, parse failure, or bad self-signature
pub fn decrypt_private_key_with_mpass(
    mpass: &str,
    secret_key_asc: &str,
) -> Result<SignedSecretKey, String> {
    let (secret_key, _) = SignedSecretKey::from_string(secret_key_asc)
        .map_err(|e| format!("Failed to parse secret key: {e}"))?;

    secret_key
        .verify()
        .map_err(|e| format!("Key self-signature verification failed: {e}"))?;

    let pw = Password::from(mpass);

    // pgp 0.17 unlock signature: unlock(&Password, |key_material: &[u8], _| -> Result<()>)
    secret_key
        .primary_key
        .unlock(&pw, |_, _| Ok(()))
        .map_err(|e| format!("Wrong master password (S2K unlock failed): {e}"))?;

    Ok(secret_key)
}