//! Tests for `crypt::session_key` — PKESK session-key encryption with PGP keys.

mod common;
use common::*;

use crypto::crypt::{
    decrypt_session_key_with_private_key, encrypt_session_key_with_public_key,
    generate_aes_session_key,
};
use pgp::composed::{Deserializable, SignedSecretKey};

// ── encrypt_session_key_with_public_key ───────────────────────────────────────

#[test]
fn test_encrypt_session_key_returns_ok() {
    println!("\n[TEST] test_encrypt_session_key_returns_ok");
    let (_, pk_asc) = make_plaintext_pgp_keypair();
    let session_key = generate_aes_session_key();

    let result = encrypt_session_key_with_public_key(&session_key, &pk_asc);
    println!("  Result is Ok: {}", result.is_ok());
    if let Err(ref e) = result {
        println!("  Error: {e}");
    }
    assert!(result.is_ok());
    println!("  ✓ Session key encrypted to PGP public key successfully");
}

#[test]
fn test_encrypt_session_key_output_is_pgp_message() {
    println!("\n[TEST] test_encrypt_session_key_output_is_pgp_message");
    let (_, pk_asc) = make_plaintext_pgp_keypair();
    let session_key = generate_aes_session_key();

    let asc = encrypt_session_key_with_public_key(&session_key, &pk_asc)
        .expect("encrypt session key");
    println!("  First 80 chars: {}", &asc[..80.min(asc.len())]);
    assert!(asc.contains("BEGIN PGP MESSAGE"), "Output must be a PGP message");
    assert!(asc.contains("END PGP MESSAGE"), "Output must have PGP message footer");
    println!("  ✓ Output is valid ASCII-armored PGP message");
}

#[test]
fn test_encrypt_session_key_same_key_different_ciphertexts() {
    println!("\n[TEST] test_encrypt_session_key_same_key_different_ciphertexts");
    let (_, pk_asc) = make_plaintext_pgp_keypair();
    let session_key = generate_aes_session_key();

    let msg_a = encrypt_session_key_with_public_key(&session_key, &pk_asc).expect("encrypt a");
    let msg_b = encrypt_session_key_with_public_key(&session_key, &pk_asc).expect("encrypt b");

    // Different session key packets (random ephemeral values in PKESK)
    assert_ne!(msg_a, msg_b, "Each PKESK encryption must produce a different ciphertext");
    println!("  ✓ PGP PKESK produces different output each call (random padding / ephemeral)");
}

#[test]
fn test_encrypt_session_key_invalid_public_key_returns_err() {
    println!("\n[TEST] test_encrypt_session_key_invalid_public_key_returns_err");
    let session_key = generate_aes_session_key();
    let result = encrypt_session_key_with_public_key(&session_key, "not-a-pgp-key");
    println!("  Result is Err: {}", result.is_err());
    assert!(result.is_err());
    println!("  ✓ Invalid public key correctly returns Err");
}

// ── decrypt_session_key_with_private_key ──────────────────────────────────────

#[test]
fn test_session_key_pkesk_round_trip() {
    println!("\n[TEST] test_session_key_pkesk_round_trip");
    let (plain_sk_asc, pk_asc) = make_plaintext_pgp_keypair();
    let session_key = generate_aes_session_key();
    println!("  Original session key: {}", hex(&session_key));

    // Encrypt to the public key
    let encrypted_msg = encrypt_session_key_with_public_key(&session_key, &pk_asc)
        .expect("encrypt session key");

    // Decrypt with the matching private key (empty passphrase — plaintext key)
    let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");
    let recovered =
        decrypt_session_key_with_private_key(&encrypted_msg, &plain_sk, "")
            .expect("decrypt session key");

    println!("  Recovered session key: {}", hex(&recovered));
    assert_eq!(session_key, recovered, "Recovered key must match the original");
    println!("  ✓ PKESK session key round-trip: key fully recovered");
}

#[test]
fn test_decrypt_session_key_wrong_private_key_returns_err() {
    println!("\n[TEST] test_decrypt_session_key_wrong_private_key_returns_err");
    let (_, pk_asc) = make_plaintext_pgp_keypair();
    let (wrong_sk_asc, _) = make_plaintext_pgp_keypair(); // different keypair
    let session_key = generate_aes_session_key();

    let encrypted_msg = encrypt_session_key_with_public_key(&session_key, &pk_asc)
        .expect("encrypt session key");

    let (wrong_sk, _) = SignedSecretKey::from_string(&wrong_sk_asc).expect("parse wrong sk");
    let result = decrypt_session_key_with_private_key(&encrypted_msg, &wrong_sk, "");
    println!("  Result is Err: {}", result.is_err());
    assert!(result.is_err(), "Wrong private key must fail decryption");
    println!("  ✓ Wrong private key correctly rejected");
}

#[test]
fn test_decrypt_session_key_garbage_input_returns_err() {
    println!("\n[TEST] test_decrypt_session_key_garbage_input_returns_err");
    let (plain_sk_asc, _) = make_plaintext_pgp_keypair();
    let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");

    let result = decrypt_session_key_with_private_key("not-a-pgp-message", &plain_sk, "");
    assert!(result.is_err());
    println!("  ✓ Garbage ciphertext correctly returns Err");
}