//! Shared test helpers.
//!
//! Imported by every integration test file as:
//! ```rust
//! mod common;
//! use common::*;
//! ```

use pgp::composed::{
    ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey,
};
use pgp::ser::Serialize;
use pgp::types::Password;
use rand::thread_rng;

pub const MASTER_PASS: &str = "test-master-password-123!";

/// Hex-encodes a byte slice for readable test output.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Creates a plaintext (no S2K passphrase) Ed25519 PGP keypair.
///
/// Returns `(secret_key_asc, public_key_asc)`.
/// Use this when you need a key to pass to `encrypt_session_key_with_public_key`
/// without going through the S2K protect/unprotect cycle.
pub fn make_plaintext_pgp_keypair() -> (String, String) {
    let mut rng = thread_rng();
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .can_certify(true)
        .can_authenticate(true)
        .primary_user_id("Test <test@example.com>".into())
        .passphrase(None) // plaintext — no S2K protection
        .build()
        .expect("build params");

    let sk = params.generate(&mut rng).expect("generate");
    let pw = Password::from(""); // empty password for plaintext key
    let ssk: SignedSecretKey = sk.sign(&mut rng, &pw).expect("sign");
    let spk: SignedPublicKey = ssk.signed_public_key();

    let sk_asc = ssk
        .to_armored_string(ArmorOptions::default())
        .expect("armor sk");
    let pk_asc = spk
        .to_armored_string(ArmorOptions::default())
        .expect("armor pk");

    (sk_asc, pk_asc)
}

/// Creates an S2K-protected Ed25519 PGP keypair using [`MASTER_PASS`].
///
/// Returns `(protected_secret_key_asc, public_key_asc)`.
/// Use this when testing `decrypt_private_key_with_mpass`.
pub fn make_s2k_pgp_keypair() -> (String, String) {
    let (plain_sk_asc, pk_asc) = make_plaintext_pgp_keypair();
    let protected = crypto::crypt::encrypt_private_key(MASTER_PASS, &plain_sk_asc)
        .expect("encrypt_private_key in test fixture");
    (protected, pk_asc)
}