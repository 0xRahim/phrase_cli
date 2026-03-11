//! Tests for `crypt::keys` — PGP keypair generation and S2K protection.

mod common;
use common::*;

use crypto::crypt::{decrypt_private_key_with_mpass, encrypt_private_key, generate_key_pairs};
use pgp::composed::Deserializable;
use pgp::composed::SignedSecretKey;
use pgp::types::KeyDetails;

// ── generate_key_pairs ────────────────────────────────────────────────────────

#[test]
fn test_generate_key_pairs_does_not_panic() {
    println!("\n[TEST] test_generate_key_pairs_does_not_panic");
    // Smoke test — just verify it runs to completion without panicking
    generate_key_pairs();
    println!("  ✓ generate_key_pairs() completed without panic");
}

// ── encrypt_private_key ───────────────────────────────────────────────────────

#[test]
fn test_encrypt_private_key_produces_pgp_armor() {
    println!("\n[TEST] test_encrypt_private_key_produces_pgp_armor");
    let (plain_sk_asc, _) = make_plaintext_pgp_keypair();

    let result = encrypt_private_key(MASTER_PASS, &plain_sk_asc);
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());

    let asc = result.unwrap();
    println!("  First 80 chars: {}", &asc[..80.min(asc.len())]);
    assert!(asc.contains("BEGIN PGP PRIVATE KEY BLOCK"), "Missing PGP header");
    assert!(asc.contains("END PGP PRIVATE KEY BLOCK"), "Missing PGP footer");
    println!("  ✓ Output is valid ASCII-armored PGP private key block");
}

#[test]
fn test_encrypt_private_key_output_is_parseable() {
    println!("\n[TEST] test_encrypt_private_key_output_is_parseable");
    let (plain_sk_asc, _) = make_plaintext_pgp_keypair();
    let protected_asc =
        encrypt_private_key(MASTER_PASS, &plain_sk_asc).expect("encrypt_private_key");

    let parse_result = SignedSecretKey::from_string(&protected_asc);
    assert!(
        parse_result.is_ok(),
        "Protected key must be re-parseable: {:?}",
        parse_result.err()
    );
    println!("  ✓ Protected key round-trips through ASCII armor");
}

#[test]
fn test_encrypt_private_key_garbage_input_returns_err() {
    println!("\n[TEST] test_encrypt_private_key_garbage_input_returns_err");
    let result = encrypt_private_key(MASTER_PASS, "this is not a pgp key");
    println!("  Result is Err: {}", result.is_err());
    if let Err(ref e) = result {
        println!("  Error: {e}");
    }
    assert!(result.is_err());
    println!("  ✓ Garbage input correctly returns Err");
}

// ── decrypt_private_key_with_mpass ────────────────────────────────────────────

#[test]
fn test_decrypt_private_key_correct_mpass_succeeds() {
    println!("\n[TEST] test_decrypt_private_key_correct_mpass_succeeds");
    let (sk_asc, _) = make_s2k_pgp_keypair();

    let result = decrypt_private_key_with_mpass(MASTER_PASS, &sk_asc);
    println!("  Result is Ok: {}", result.is_ok());
    assert!(result.is_ok(), "{:?}", result.err());

    // KeyDetails trait must be in scope for .key_id()
    println!("  Key ID: {:?}", result.unwrap().key_id());
    println!("  ✓ Correct master password successfully unlocks the key");
}

#[test]
fn test_decrypt_private_key_wrong_mpass_returns_err() {
    println!("\n[TEST] test_decrypt_private_key_wrong_mpass_returns_err");
    let (sk_asc, _) = make_s2k_pgp_keypair();

    let result = decrypt_private_key_with_mpass("completely-wrong-password", &sk_asc);
    println!("  Result is Err: {}", result.is_err());
    if let Err(ref e) = result {
        println!("  Error: {e}");
    }
    assert!(result.is_err());
    println!("  ✓ Wrong master password rejected by S2K unlock");
}

#[test]
fn test_decrypt_private_key_garbage_input_returns_err() {
    println!("\n[TEST] test_decrypt_private_key_garbage_input_returns_err");
    let result = decrypt_private_key_with_mpass(MASTER_PASS, "not-a-key");
    assert!(result.is_err());
    println!("  ✓ Garbage input correctly returns Err");
}