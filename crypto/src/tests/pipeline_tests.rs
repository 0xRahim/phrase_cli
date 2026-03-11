//! End-to-end pipeline tests.
//!
//! These tests exercise the **full hybrid encryption pipeline** as it would
//! be used by the password manager:
//!
//! ```text
//! STORE
//!   plaintext ──AES-256-GCM──► encrypted_blob
//!   session_key ──PKESK──► encrypted_session_key_msg
//!
//! RETRIEVE
//!   master_password ──S2K──► SignedSecretKey
//!   encrypted_session_key_msg ──PKESK──► session_key
//!   encrypted_blob ──AES-256-GCM──► plaintext
//! ```

mod common;
use common::*;

use crypto::crypt::{
    decrypt_private_key_with_mpass, decrypt_session_key_with_private_key,
    decrypt_string_with_aes, encrypt_session_key_with_public_key,
    encrypt_string_with_aes, generate_aes_session_key,
};
use pgp::composed::{Deserializable, SignedSecretKey};

#[test]
fn test_full_pipeline_single_entry() {
    println!("\n[TEST] test_full_pipeline_single_entry");
    println!("  Scenario: store one vault entry, then retrieve it\n");

    // ── Vault setup ────────────────────────────────────────────────────────────
    // In a real app: generate the keypair once when creating the vault.
    // The public key is stored in vault metadata.
    // The private key is S2K-protected via encrypt_private_key and stored on disk.
    // We use a plaintext key here to skip S2K for brevity; see the S2K test below.
    let (plain_sk_asc, pk_asc) = make_plaintext_pgp_keypair();
    println!("  [setup] PGP keypair generated");

    // ── STORE ──────────────────────────────────────────────────────────────────

    let password_to_store = "my-bank-password-abc123!";
    println!("  [store] Plaintext password  : {password_to_store}");

    // 1. Generate a unique AES session key for this entry
    let session_key = generate_aes_session_key();
    println!("  [store] Session key         : {}", hex(&session_key));

    // 2. Encrypt the password with the session key
    let encrypted_blob = encrypt_string_with_aes(password_to_store, &session_key)
        .expect("AES encrypt");
    println!("  [store] Encrypted blob      : {} bytes", encrypted_blob.len());

    // 3. Encrypt the session key to the public key so only the private key can unwrap it
    let encrypted_sk_msg = encrypt_session_key_with_public_key(&session_key, &pk_asc)
        .expect("PKESK wrap");
    println!("  [store] PKESK message       : {} chars", encrypted_sk_msg.len());

    // ── RETRIEVE ───────────────────────────────────────────────────────────────

    // 4. Parse the private key (in a real app it's S2K-protected; user supplies mpass)
    let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");

    // 5. Unwrap the session key using the private key
    let recovered_session_key =
        decrypt_session_key_with_private_key(&encrypted_sk_msg, &plain_sk, "")
            .expect("PKESK unwrap");
    println!("  [retrieve] Session key      : {}", hex(&recovered_session_key));

    // 6. Decrypt the password blob using the session key
    let recovered_password =
        decrypt_string_with_aes(&encrypted_blob, &recovered_session_key)
            .expect("AES decrypt");
    println!("  [retrieve] Recovered pw     : {recovered_password}");

    assert_eq!(session_key, recovered_session_key, "Session key must survive PKESK round-trip");
    assert_eq!(password_to_store, recovered_password, "Plaintext must survive full pipeline");
    println!("\n  ✓ Full single-entry pipeline verified");
}

#[test]
fn test_full_pipeline_multiple_entries_independent_keys() {
    println!("\n[TEST] test_full_pipeline_multiple_entries_independent_keys");
    println!("  Scenario: store 3 vault entries — each must use a different session key\n");

    let (plain_sk_asc, pk_asc) = make_plaintext_pgp_keypair();
    let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");

    let entries = [
        "github-password-1",
        "email-password-2",
        "bank-password-3",
    ];

    // Store all entries
    let stored: Vec<(Vec<u8>, String, [u8; 32])> = entries
        .iter()
        .map(|pw| {
            let sk = generate_aes_session_key();
            let blob = encrypt_string_with_aes(pw, &sk).expect("AES encrypt");
            let msg = encrypt_session_key_with_public_key(&sk, &pk_asc).expect("PKESK wrap");
            (blob, msg, sk)
        })
        .collect();

    // Verify all session keys differ
    assert_ne!(stored[0].2, stored[1].2, "Session keys must be unique per entry");
    assert_ne!(stored[1].2, stored[2].2, "Session keys must be unique per entry");
    println!("  ✓ All 3 entries have distinct session keys");

    // Retrieve and verify each entry independently
    for (i, ((blob, msg, _), &expected_pw)) in stored.iter().zip(entries.iter()).enumerate() {
        let sk = decrypt_session_key_with_private_key(msg, &plain_sk, "")
            .expect("PKESK unwrap");
        let pw = decrypt_string_with_aes(blob, &sk).expect("AES decrypt");
        assert_eq!(expected_pw, pw, "Entry {i} must decrypt correctly");
        println!("  Entry {i} ✓  recovered: {pw}");
    }

    println!("\n  ✓ All entries independently encrypted and decrypted correctly");
}

#[test]
fn test_wrong_session_key_cannot_decrypt_entry() {
    println!("\n[TEST] test_wrong_session_key_cannot_decrypt_entry");

    let key_a = generate_aes_session_key();
    let key_b = generate_aes_session_key();

    let blob = encrypt_string_with_aes("secret-password", &key_a).expect("encrypt");
    let result = decrypt_string_with_aes(&blob, &key_b);

    assert!(result.is_err(), "Wrong session key must fail AES-GCM auth check");
    println!("  ✓ Cross-entry key confusion correctly rejected by GCM");
}