/// Password-manager hybrid encryption library.
///
/// # Architecture
///
/// ```text
/// master password ──Argon2id──► wrapping key ──AES-256-GCM──► protected private key
///                                                                        │
///              PGP private key ◄──────────────────────────────────────-┘
///                    │
///                    │  (PKESK decrypt)
///                    ▼
///           AES-256 session key  ◄── stored encrypted alongside every entry
///                    │
///                    │  (AES-256-GCM decrypt)
///                    ▼
///              plaintext password
/// ```
///
/// # Modules
/// - [`crypt::keys`]        — PGP keypair generation and S2K passphrase protection
/// - [`crypt::aes`]         — AES-256-GCM symmetric encryption for password strings
/// - [`crypt::session_key`] — PKESK session-key wrap/unwrap via PGP public key

pub mod crypt;