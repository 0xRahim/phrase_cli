//! `crypt` — top-level encryption module.
//!
//! Submodules are kept internal; only this file decides what is public.
//! Consumers should import from `crypt::*` or use the explicit paths below.

// ── private helpers shared across submodules ─────────────────────────────────
pub(crate) mod helpers;

// ── public submodules ─────────────────────────────────────────────────────────
pub mod aes;
pub mod keys;
pub mod session_key;

// ── flat re-exports so callers can write `crypt::generate_aes_session_key()` ─
pub use aes::{
    decrypt_string_with_aes,
    encrypt_string_with_aes,
    generate_aes_session_key,
};
pub use keys::{
    decrypt_private_key_with_mpass,
    encrypt_private_key,
    generate_key_pairs,
};
pub use session_key::{
    decrypt_session_key_with_private_key,
    decrypt_x25519_private_key_with_mpass,
    encrypt_session_key_with_public_key,
    encrypt_x25519_private_key_with_mpass,
    generate_x25519_keypair,
};