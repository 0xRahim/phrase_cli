pub mod crypt {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
        Aes256Gcm, Key, Nonce,
    };
    use hkdf::Hkdf;
    use pgp::composed::{
        ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey,
    };
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, Password};
    use rand::{rngs::OsRng, thread_rng, RngCore};
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};

    // ═════════════════════════════════════════════════════════════════════════
    // PGP KEY GENERATION  (used for signing / identity only)
    // ═════════════════════════════════════════════════════════════════════════

    /// Generates an Ed25519 PGP keypair and prints both keys as ASCII armor.
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

    // ═════════════════════════════════════════════════════════════════════════
    // PGP PRIVATE KEY  ── S2K PASSPHRASE PROTECTION
    // ═════════════════════════════════════════════════════════════════════════

    /// Re-generates an S2K-passphrase-protected PGP private key using the
    /// same user ID as the supplied key. The pgp crate applies
    /// iterated+salted SHA-256 → AES-256-CFB at key-generation time.
    ///
    /// # Arguments
    /// * `mpass`          - Master password to protect the key
    /// * `secret_key_asc` - Existing ASCII-armored key (user ID is extracted from it)
    ///
    /// # Returns
    /// * `Ok(String)` - ASCII-armored S2K-protected private key
    pub fn encrypt_private_key(mpass: &str, secret_key_asc: &str) -> Result<String, String> {
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

    /// Parses, verifies, and eagerly validates the master password against an
    /// S2K-protected PGP private key. Returns the unlocked `SignedSecretKey`.
    ///
    /// # Arguments
    /// * `mpass`          - Master password used when the key was protected
    /// * `secret_key_asc` - ASCII-armored S2K-protected PGP private key
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

        // Eagerly unlock to validate the password now rather than silently failing later.
        // Closure signature in pgp 0.17: |key_material: &[u8], _extra| -> Result<()>
        secret_key
            .primary_key
            .unlock(&pw, |_, _| Ok(()))
            .map_err(|e| format!("Wrong master password (S2K unlock failed): {e}"))?;

        Ok(secret_key)
    }

    // ═════════════════════════════════════════════════════════════════════════
    // AES-256-GCM  ── SYMMETRIC ENCRYPTION (password / secret strings)
    // ═════════════════════════════════════════════════════════════════════════

    /// Generates a cryptographically random 32-byte AES-256 session key.
    /// Generate a **fresh key for every password entry** stored in the vault.
    pub fn generate_aes_session_key() -> [u8; 32] {
        Aes256Gcm::generate_key(&mut AesOsRng).into()
    }

    /// Encrypts `plaintext` with AES-256-GCM.
    ///
    /// Blob format: `nonce(12) ++ ciphertext(n) ++ tag(16)`
    /// The nonce is randomly generated and prepended — no separate storage needed.
    pub fn encrypt_string_with_aes(
        plaintext: &str,
        session_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

        let mut blob = nonce.to_vec();   // 12 bytes
        blob.extend_from_slice(&ciphertext); // n + 16-byte tag
        Ok(blob)
    }

    /// Decrypts an AES-256-GCM blob produced by `encrypt_string_with_aes`.
    ///
    /// The GCM auth tag guarantees integrity — any tampering or wrong key
    /// returns `Err` immediately.
    ///
    /// Blob format: `nonce(12) ++ ciphertext(n) ++ tag(16)`
    pub fn decrypt_string_with_aes(
        blob: &[u8],
        session_key: &[u8; 32],
    ) -> Result<String, String> {
        if blob.len() < 28 {
            return Err(format!("Blob too short: {} bytes (minimum 28)", blob.len()));
        }

        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES-GCM decryption failed (wrong key or tampered): {e}"))?;

        String::from_utf8(plaintext)
            .map_err(|e| format!("Decrypted bytes are not valid UTF-8: {e}"))
    }

    // ═════════════════════════════════════════════════════════════════════════
    // X25519 KEYPAIR  ── ASYMMETRIC LAYER FOR SESSION-KEY PROTECTION
    //
    // The pgp crate's Message-level encryption API has never been stable in
    // any 0.x release (method names change every minor version, internal types
    // are not publicly constructable). X25519/ECIES is cryptographically
    // identical to OpenPGP's ECDH key-encryption and uses fully stable crates.
    //
    // Full pipeline:
    //   master password ──Argon2id──► wrapping key ──AES-256-GCM──► protected X25519 private key
    //   X25519 public key ──ECIES──► encrypted session key blob
    //   session key ──AES-256-GCM──► encrypted password entry
    // ═════════════════════════════════════════════════════════════════════════

    /// Generates a fresh X25519 keypair.
    ///
    /// Returns `(private_key[32], public_key[32])`.
    /// - **Public key**  → store in vault metadata (plaintext is fine)
    /// - **Private key** → must be protected with `encrypt_x25519_private_key_with_mpass`
    pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    /// Protects the 32-byte X25519 private key under the master password.
    ///
    /// KDF: Argon2id (m=64MB, t=3, p=1) → 32-byte wrapping key → AES-256-GCM.
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

    /// Encrypts a 32-byte AES session key to a recipient's X25519 public key
    /// using ECIES: ephemeral ECDH → HKDF-SHA256 → AES-256-GCM.
    /// A fresh ephemeral keypair is generated every call (forward secrecy).
    ///
    /// Blob format: `eph_pub(32) ++ nonce(12) ++ ciphertext(32) ++ tag(16)` = **92 bytes**
    pub fn encrypt_session_key_with_public_key(
        session_key: &[u8; 32],
        recipient_public_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let recipient_pub = X25519Public::from(*recipient_public_key);
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

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

    /// Recovers a 32-byte AES session key from an ECIES blob using the
    /// recipient's X25519 private key.
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

    // ═════════════════════════════════════════════════════════════════════════
    // PRIVATE HELPERS
    // ═════════════════════════════════════════════════════════════════════════

    /// Argon2id: password + 16-byte salt → 32-byte output key.
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
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::crypt::*;
    use pgp::composed::{
        ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey,
    };
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, Password};
    use rand::thread_rng;

    const MASTER_PASS: &str = "test-master-password-123!";

    // ── test helpers ──────────────────────────────────────────────────────────

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Plaintext (no passphrase) PGP keypair — used for testing encrypt_private_key.
    fn make_plaintext_pgp_keypair() -> (String, String) {
        let mut rng = thread_rng();
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true).can_certify(true).can_authenticate(true)
            .primary_user_id("Test <test@example.com>".into())
            .passphrase(None)
            .build()
            .expect("build params");
        let sk = params.generate(&mut rng).expect("generate");
        let pw = Password::from("");
        let ssk: SignedSecretKey = sk.sign(&mut rng, &pw).expect("sign");
        let spk: SignedPublicKey = ssk.signed_public_key();
        let sk_asc = ssk.to_armored_string(ArmorOptions::default()).expect("armor sk");
        let pk_asc = spk.to_armored_string(ArmorOptions::default()).expect("armor pk");
        (sk_asc, pk_asc)
    }

    /// Returns an S2K-protected PGP private key (armored) + its public key (armored).
    fn make_s2k_pgp_keypair() -> (String, String) {
        let (plain_sk_asc, pk_asc) = make_plaintext_pgp_keypair();
        let protected = encrypt_private_key(MASTER_PASS, &plain_sk_asc)
            .expect("encrypt_private_key");
        (protected, pk_asc)
    }

    // ─── generate_key_pairs ───────────────────────────────────────────────────

    #[test]
    fn test_generate_key_pairs_does_not_panic() {
        println!("\n[TEST] test_generate_key_pairs_does_not_panic");
        generate_key_pairs();
        println!("  ✓ generate_key_pairs() completed without panic");
    }

    // ─── encrypt_private_key / decrypt_private_key_with_mpass ────────────────

    #[test]
    fn test_encrypt_private_key_produces_pgp_armor() {
        println!("\n[TEST] test_encrypt_private_key_produces_pgp_armor");
        let (plain_sk_asc, _) = make_plaintext_pgp_keypair();
        let result = encrypt_private_key(MASTER_PASS, &plain_sk_asc);
        assert!(result.is_ok(), "{:?}", result.err());
        let asc = result.unwrap();
        println!("  First 80 chars: {}", &asc[..80.min(asc.len())]);
        assert!(asc.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(asc.contains("END PGP PRIVATE KEY BLOCK"));
        println!("  ✓ Output is valid PGP private key armor");
    }

    #[test]
    fn test_encrypt_private_key_garbage_input_fails() {
        println!("\n[TEST] test_encrypt_private_key_garbage_input_fails");
        let result = encrypt_private_key(MASTER_PASS, "not-a-pgp-key");
        println!("  Result is Err: {}", result.is_err());
        assert!(result.is_err());
        println!("  ✓ Garbage input returns Err");
    }

    #[test]
    fn test_decrypt_private_key_correct_mpass_succeeds() {
        println!("\n[TEST] test_decrypt_private_key_correct_mpass_succeeds");
        let (sk_asc, _) = make_s2k_pgp_keypair();
        let result = decrypt_private_key_with_mpass(MASTER_PASS, &sk_asc);
        println!("  Result is Ok: {}", result.is_ok());
        assert!(result.is_ok(), "{:?}", result.err());
        println!("  Key ID: {:?}", result.unwrap().key_id());
        println!("  ✓ Correct master password unlocks the key");
    }

    #[test]
    fn test_decrypt_private_key_wrong_mpass_fails() {
        println!("\n[TEST] test_decrypt_private_key_wrong_mpass_fails");
        let (sk_asc, _) = make_s2k_pgp_keypair();
        let result = decrypt_private_key_with_mpass("wrong-password", &sk_asc);
        println!("  Result is Err: {}", result.is_err());
        if let Err(ref e) = result { println!("  Error: {e}"); }
        assert!(result.is_err());
        println!("  ✓ Wrong master password rejected");
    }

    #[test]
    fn test_decrypt_private_key_garbage_input_fails() {
        println!("\n[TEST] test_decrypt_private_key_garbage_input_fails");
        let result = decrypt_private_key_with_mpass(MASTER_PASS, "garbage");
        assert!(result.is_err());
        println!("  ✓ Garbage input returns Err");
    }

    // ─── generate_aes_session_key ─────────────────────────────────────────────

    #[test]
    fn test_aes_session_key_is_32_bytes() {
        println!("\n[TEST] test_aes_session_key_is_32_bytes");
        let key = generate_aes_session_key();
        println!("  Key: {}", hex(&key));
        assert_eq!(key.len(), 32);
        println!("  ✓ 32-byte (256-bit) session key");
    }

    #[test]
    fn test_aes_session_key_unique_each_call() {
        println!("\n[TEST] test_aes_session_key_unique_each_call");
        let a = generate_aes_session_key();
        let b = generate_aes_session_key();
        println!("  A: {}", hex(&a));
        println!("  B: {}", hex(&b));
        assert_ne!(a, b);
        println!("  ✓ CSPRNG produces unique keys");
    }

    // ─── encrypt_string_with_aes / decrypt_string_with_aes ───────────────────

    #[test]
    fn test_aes_encrypt_decrypt_round_trip() {
        println!("\n[TEST] test_aes_encrypt_decrypt_round_trip");
        let key = generate_aes_session_key();
        let original = "correct-horse-battery-staple";
        let blob = encrypt_string_with_aes(original, &key).expect("encrypt");
        println!("  Blob: {} bytes  (12 nonce + {} ciphertext+tag)", blob.len(), blob.len()-12);
        let recovered = decrypt_string_with_aes(&blob, &key).expect("decrypt");
        println!("  Recovered: {recovered}");
        assert_eq!(original, recovered);
        println!("  ✓ AES round-trip ok");
    }

    #[test]
    fn test_aes_same_plaintext_different_nonces() {
        println!("\n[TEST] test_aes_same_plaintext_different_nonces");
        let key = generate_aes_session_key();
        let blob_a = encrypt_string_with_aes("hello", &key).expect("a");
        let blob_b = encrypt_string_with_aes("hello", &key).expect("b");
        println!("  Nonce A: {}", hex(&blob_a[..12]));
        println!("  Nonce B: {}", hex(&blob_b[..12]));
        assert_ne!(blob_a, blob_b, "Nonces must differ — no nonce reuse");
        println!("  ✓ Fresh nonce generated each call");
    }

    #[test]
    fn test_aes_wrong_key_fails() {
        println!("\n[TEST] test_aes_wrong_key_fails");
        let key_a = generate_aes_session_key();
        let key_b = generate_aes_session_key();
        let blob = encrypt_string_with_aes("secret", &key_a).expect("encrypt");
        let result = decrypt_string_with_aes(&blob, &key_b);
        assert!(result.is_err());
        println!("  ✓ Wrong key rejected by GCM auth tag");
    }

    #[test]
    fn test_aes_tampered_ciphertext_fails() {
        println!("\n[TEST] test_aes_tampered_ciphertext_fails");
        let key = generate_aes_session_key();
        let mut blob = encrypt_string_with_aes("tamper me", &key).expect("encrypt");
        blob[13] ^= 0xFF; // flip a ciphertext byte
        let result = decrypt_string_with_aes(&blob, &key);
        assert!(result.is_err());
        println!("  ✓ Tampered ciphertext rejected by GCM auth tag");
    }

    #[test]
    fn test_aes_blob_too_short_fails() {
        println!("\n[TEST] test_aes_blob_too_short_fails");
        let key = generate_aes_session_key();
        let result = decrypt_string_with_aes(&[0u8; 10], &key);
        assert!(result.is_err());
        println!("  ✓ Short blob returns Err");
    }

    // ─── generate_x25519_keypair ──────────────────────────────────────────────

    #[test]
    fn test_x25519_keypair_lengths() {
        println!("\n[TEST] test_x25519_keypair_lengths");
        let (priv_key, pub_key) = generate_x25519_keypair();
        println!("  Private: {}", hex(&priv_key));
        println!("  Public : {}", hex(&pub_key));
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
        println!("  ✓ Both keys are 32 bytes");
    }

    #[test]
    fn test_x25519_keypair_unique() {
        println!("\n[TEST] test_x25519_keypair_unique");
        let (a, _) = generate_x25519_keypair();
        let (b, _) = generate_x25519_keypair();
        assert_ne!(a, b);
        println!("  ✓ Keypairs are unique");
    }

    // ─── encrypt/decrypt X25519 private key with master password ─────────────

    #[test]
    fn test_x25519_private_key_protect_round_trip() {
        println!("\n[TEST] test_x25519_private_key_protect_round_trip");
        let (priv_key, _) = generate_x25519_keypair();
        println!("  Original : {}", hex(&priv_key));
        let blob = encrypt_x25519_private_key_with_mpass(MASTER_PASS, &priv_key).expect("protect");
        println!("  Blob     : {} bytes (expected 76)", blob.len());
        assert_eq!(blob.len(), 76, "salt(16)+nonce(12)+ct(32)+tag(16)=76");
        let recovered = decrypt_x25519_private_key_with_mpass(MASTER_PASS, &blob).expect("unprotect");
        println!("  Recovered: {}", hex(&recovered));
        assert_eq!(priv_key, recovered);
        println!("  ✓ X25519 private key protect → unprotect round-trip ok");
    }

    #[test]
    fn test_x25519_private_key_wrong_mpass_fails() {
        println!("\n[TEST] test_x25519_private_key_wrong_mpass_fails");
        let (priv_key, _) = generate_x25519_keypair();
        let blob = encrypt_x25519_private_key_with_mpass(MASTER_PASS, &priv_key).expect("protect");
        let result = decrypt_x25519_private_key_with_mpass("wrong-password", &blob);
        assert!(result.is_err());
        println!("  ✓ Wrong master password rejected by AES-GCM auth tag");
    }

    #[test]
    fn test_x25519_different_salts_per_call() {
        println!("\n[TEST] test_x25519_different_salts_per_call");
        let (priv_key, _) = generate_x25519_keypair();
        let blob_a = encrypt_x25519_private_key_with_mpass(MASTER_PASS, &priv_key).expect("a");
        let blob_b = encrypt_x25519_private_key_with_mpass(MASTER_PASS, &priv_key).expect("b");
        // First 16 bytes are the Argon2 salt — must differ
        assert_ne!(&blob_a[..16], &blob_b[..16], "Argon2 salt must be random each call");
        println!("  ✓ Fresh Argon2 salt generated each call");
    }

    // ─── encrypt/decrypt session key with X25519 (ECIES) ─────────────────────

    #[test]
    fn test_encrypt_session_key_blob_is_92_bytes() {
        println!("\n[TEST] test_encrypt_session_key_blob_is_92_bytes");
        let (_, pub_key) = generate_x25519_keypair();
        let session_key = generate_aes_session_key();
        let blob = encrypt_session_key_with_public_key(&session_key, &pub_key).expect("encrypt");
        println!("  Blob: {} bytes (expected 92 = eph_pub(32)+nonce(12)+ct(32)+tag(16))", blob.len());
        assert_eq!(blob.len(), 92);
        println!("  ✓ Blob is exactly 92 bytes");
    }

    #[test]
    fn test_session_key_ecies_round_trip() {
        println!("\n[TEST] test_session_key_ecies_round_trip");
        let (priv_key, pub_key) = generate_x25519_keypair();
        let session_key = generate_aes_session_key();
        println!("  Original : {}", hex(&session_key));
        let blob = encrypt_session_key_with_public_key(&session_key, &pub_key).expect("encrypt");
        let recovered = decrypt_session_key_with_private_key(&blob, &priv_key).expect("decrypt");
        println!("  Recovered: {}", hex(&recovered));
        assert_eq!(session_key, recovered);
        println!("  ✓ ECIES session key round-trip ok");
    }

    #[test]
    fn test_session_key_wrong_private_key_fails() {
        println!("\n[TEST] test_session_key_wrong_private_key_fails");
        let (_, pub_key) = generate_x25519_keypair();
        let (wrong_priv, _) = generate_x25519_keypair();
        let session_key = generate_aes_session_key();
        let blob = encrypt_session_key_with_public_key(&session_key, &pub_key).expect("encrypt");
        let result = decrypt_session_key_with_private_key(&blob, &wrong_priv);
        assert!(result.is_err());
        println!("  ✓ Wrong private key rejected by AES-GCM auth tag");
    }

    #[test]
    fn test_session_key_fresh_ephemeral_each_call() {
        println!("\n[TEST] test_session_key_fresh_ephemeral_each_call");
        let (_, pub_key) = generate_x25519_keypair();
        let session_key = generate_aes_session_key();
        let blob_a = encrypt_session_key_with_public_key(&session_key, &pub_key).expect("a");
        let blob_b = encrypt_session_key_with_public_key(&session_key, &pub_key).expect("b");
        // First 32 bytes are the ephemeral public key — must differ each call
        assert_ne!(&blob_a[..32], &blob_b[..32], "Ephemeral key must differ each call");
        println!("  ✓ Fresh ephemeral keypair each call (forward secrecy)");
    }

    #[test]
    fn test_session_key_blob_too_short_fails() {
        println!("\n[TEST] test_session_key_blob_too_short_fails");
        let (priv_key, _) = generate_x25519_keypair();
        let result = decrypt_session_key_with_private_key(&[0u8; 50], &priv_key);
        assert!(result.is_err());
        println!("  ✓ Short blob returns Err");
    }

    // ─── FULL END-TO-END PIPELINE ─────────────────────────────────────────────

    #[test]
    fn test_full_hybrid_pipeline() {
        println!("\n[TEST] test_full_hybrid_pipeline");
        println!("  Simulating a full password manager store → retrieve cycle\n");

        let password_to_store = "my-bank-password-abc123!";
        println!("  [0] Password to store        : {password_to_store}");

        // ── Vault setup (done once when vault is created) ─────────────────────
        let (x25519_priv, x25519_pub) = generate_x25519_keypair();
        let protected_priv = encrypt_x25519_private_key_with_mpass(MASTER_PASS, &x25519_priv)
            .expect("protect X25519 private key");
        println!("  [setup] X25519 keypair generated");
        println!("  [setup] Private key blob     : {} bytes", protected_priv.len());

        // ── Store a password entry ─────────────────────────────────────────────
        let session_key = generate_aes_session_key();
        println!("  [store] Session key          : {}", hex(&session_key));

        let encrypted_password = encrypt_string_with_aes(password_to_store, &session_key)
            .expect("AES encrypt password");
        println!("  [store] Encrypted password   : {} bytes", encrypted_password.len());

        let encrypted_session_key = encrypt_session_key_with_public_key(&session_key, &x25519_pub)
            .expect("ECIES wrap session key");
        println!("  [store] Encrypted session key: {} bytes", encrypted_session_key.len());

        // ── Retrieve a password entry (user supplies master password) ──────────
        let recovered_priv = decrypt_x25519_private_key_with_mpass(MASTER_PASS, &protected_priv)
            .expect("unprotect X25519 private key");
        println!("  [retrieve] Private key recovered");

        let recovered_session_key =
            decrypt_session_key_with_private_key(&encrypted_session_key, &recovered_priv)
                .expect("ECIES unwrap session key");
        println!("  [retrieve] Session key       : {}", hex(&recovered_session_key));

        let recovered_password =
            decrypt_string_with_aes(&encrypted_password, &recovered_session_key)
                .expect("AES decrypt password");
        println!("  [retrieve] Password          : {recovered_password}");

        assert_eq!(x25519_priv, recovered_priv,    "private key must survive protect/unprotect");
        assert_eq!(session_key, recovered_session_key, "session key must survive ECIES wrap/unwrap");
        assert_eq!(password_to_store, recovered_password, "plaintext must survive full pipeline");
        println!("\n  ✓ Full hybrid pipeline verified end-to-end");
    }
}