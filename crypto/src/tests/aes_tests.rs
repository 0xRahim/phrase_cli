//! Tests for `crypt::aes` — AES-256-GCM session key and string encryption.

mod common;
use common::*;

use crypto::crypt::{
    decrypt_string_with_aes, encrypt_string_with_aes, generate_aes_session_key,
};

// ── generate_aes_session_key ──────────────────────────────────────────────────

#[test]
fn test_session_key_is_32_bytes() {
    println!("\n[TEST] test_session_key_is_32_bytes");
    let key = generate_aes_session_key();
    println!("  Key: {}", hex(&key));
    assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
    println!("  ✓ 32-byte (256-bit) key confirmed");
}

#[test]
fn test_session_key_unique_each_call() {
    println!("\n[TEST] test_session_key_unique_each_call");
    let a = generate_aes_session_key();
    let b = generate_aes_session_key();
    println!("  Key A: {}", hex(&a));
    println!("  Key B: {}", hex(&b));
    assert_ne!(a, b, "CSPRNG must produce distinct keys on each call");
    println!("  ✓ Keys are unique across calls");
}

// ── encrypt_string_with_aes ───────────────────────────────────────────────────

#[test]
fn test_encrypt_string_returns_ok() {
    println!("\n[TEST] test_encrypt_string_returns_ok");
    let key = generate_aes_session_key();
    let result = encrypt_string_with_aes("my-password", &key);
    assert!(result.is_ok(), "{:?}", result.err());
    let blob = result.unwrap();
    println!("  Blob: {} bytes  (12 nonce + {} ct+tag)", blob.len(), blob.len() - 12);
    println!("  ✓ Encryption returned Ok");
}

#[test]
fn test_encrypt_string_blob_minimum_length() {
    println!("\n[TEST] test_encrypt_string_blob_minimum_length");
    let key = generate_aes_session_key();

    // Empty string → nonce(12) + tag(16) = 28 bytes
    let empty_blob = encrypt_string_with_aes("", &key).expect("encrypt empty");
    println!("  Empty string blob: {} bytes (expected 28)", empty_blob.len());
    assert_eq!(empty_blob.len(), 28, "nonce(12) + tag(16) = 28 for empty plaintext");

    // "hello" (5 bytes) → 12 + 5 + 16 = 33 bytes
    let hello_blob = encrypt_string_with_aes("hello", &key).expect("encrypt hello");
    println!("  'hello' blob     : {} bytes (expected 33)", hello_blob.len());
    assert_eq!(hello_blob.len(), 33, "nonce(12) + len(5) + tag(16) = 33");

    println!("  ✓ Blob lengths are structurally correct");
}

#[test]
fn test_encrypt_same_plaintext_produces_different_blobs() {
    println!("\n[TEST] test_encrypt_same_plaintext_produces_different_blobs");
    let key = generate_aes_session_key();
    let blob_a = encrypt_string_with_aes("same-password", &key).expect("first encrypt");
    let blob_b = encrypt_string_with_aes("same-password", &key).expect("second encrypt");
    println!("  Nonce A: {}", hex(&blob_a[..12]));
    println!("  Nonce B: {}", hex(&blob_b[..12]));
    assert_ne!(blob_a, blob_b, "Each encryption must use a fresh nonce");
    println!("  ✓ Fresh nonce generated every call — no nonce reuse");
}

// ── decrypt_string_with_aes ───────────────────────────────────────────────────

#[test]
fn test_aes_encrypt_decrypt_round_trip() {
    println!("\n[TEST] test_aes_encrypt_decrypt_round_trip");
    let key = generate_aes_session_key();
    let original = "correct-horse-battery-staple";

    let blob = encrypt_string_with_aes(original, &key).expect("encrypt");
    println!("  Blob: {} bytes", blob.len());

    let recovered = decrypt_string_with_aes(&blob, &key).expect("decrypt");
    println!("  Recovered: {recovered}");

    assert_eq!(original, recovered);
    println!("  ✓ AES-256-GCM round-trip: plaintext fully recovered");
}

#[test]
fn test_decrypt_wrong_key_returns_err() {
    println!("\n[TEST] test_decrypt_wrong_key_returns_err");
    let key_a = generate_aes_session_key();
    let key_b = generate_aes_session_key();
    let blob = encrypt_string_with_aes("secret", &key_a).expect("encrypt");

    let result = decrypt_string_with_aes(&blob, &key_b);
    println!("  Result is Err: {}", result.is_err());
    assert!(result.is_err(), "Wrong key must fail GCM auth check");
    println!("  ✓ Wrong key correctly rejected by GCM authentication tag");
}

#[test]
fn test_decrypt_tampered_ciphertext_returns_err() {
    println!("\n[TEST] test_decrypt_tampered_ciphertext_returns_err");
    let key = generate_aes_session_key();
    let mut blob = encrypt_string_with_aes("tamper me", &key).expect("encrypt");

    // Flip a bit in the ciphertext region (after the 12-byte nonce)
    blob[13] ^= 0xFF;
    println!("  Flipped byte 13 (ciphertext region)");

    let result = decrypt_string_with_aes(&blob, &key);
    assert!(result.is_err(), "Tampered ciphertext must fail GCM auth check");
    println!("  ✓ Tampered ciphertext correctly rejected");
}

#[test]
fn test_decrypt_short_blob_returns_err() {
    println!("\n[TEST] test_decrypt_short_blob_returns_err");
    let key = generate_aes_session_key();
    let result = decrypt_string_with_aes(&[0u8; 10], &key);
    assert!(result.is_err());
    if let Err(ref e) = result {
        println!("  Error: {e}");
    }
    println!("  ✓ Blob shorter than 28 bytes returns Err");
}