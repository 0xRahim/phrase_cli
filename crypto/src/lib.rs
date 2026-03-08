pub mod crypt {
    use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use pgp::composed::ArmorOptions;
    use pgp::composed::Deserializable;
    use pgp::composed::Message;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey};
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::packet::LiteralData;
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, Password}; // ← fix E5: KeyDetails must be in scope for .key_id()
    use rand::thread_rng;

    // ── helper: hand-craft a PGP Literal Data Packet (tag 11, new format) ────────
    //
    // PGP new-format packet layout (RFC 4880 §4.2 + §5.9):
    //   0xCB           — new-format tag byte for Literal Data (tag 11 = 0b001011, 0xC0|11 = 0xCB)
    //   <length>       — one-octet body length (works for bodies < 192 bytes)
    //   0x62  ('b')    — binary data format
    //   <fname_len>    — 1 byte: length of the filename field
    //   <fname>        — filename bytes (we use "key")
    //   <date>         — 4 bytes: modification date, zeroed
    //   <payload>      — the actual data bytes
    //
    // We hex-encode the 32-byte session key so the payload is always 64 bytes,
    // well within the one-octet length limit (< 192).
    fn build_literal_packet(payload: &[u8]) -> Vec<u8> {
        let fname = b"key";
        // body = format(1) + fname_len(1) + fname(3) + date(4) + payload
        let body_len = 1 + 1 + fname.len() + 4 + payload.len();
        assert!(
            body_len < 192,
            "payload too large for one-octet length encoding"
        );

        let mut pkt = Vec::with_capacity(2 + body_len);
        pkt.push(0xCB); // new-format Literal Data tag
        pkt.push(body_len as u8); // one-octet body length
        pkt.push(b'b'); // binary format byte
        pkt.push(fname.len() as u8); // filename length
        pkt.extend_from_slice(fname);
        pkt.extend_from_slice(&[0u8; 4]); // date = 0
        pkt.extend_from_slice(payload);
        pkt
    }

    // ─── EXISTING ────────────────────────────────────────────────────────────────

    pub fn generate_key_pairs() {
        let mut rng = thread_rng();

        let secret_key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .can_authenticate(true)
            .primary_user_id("User <user@example.com>".into())
            .passphrase(Some("your-secure-passphrase".into()))
            .build()
            .expect("Failed to build key params");

        let secret_key = secret_key_params
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
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        let secret_key_asc = signed_secret_key
            .to_armored_string(ArmorOptions::default())
            .expect("Failed to armor secret key");

        let public_key_asc = signed_public_key
            .to_armored_string(ArmorOptions::default())
            .expect("Failed to armor public key");

        println!("=== KEY INFO ===");
        println!("Key ID:      {:?}", signed_public_key.key_id());
        println!("Fingerprint: {}", fingerprint);
        println!("\n=== SECRET KEY ===\n{}", secret_key_asc);
        println!("=== PUBLIC KEY ===\n{}", public_key_asc);
    }

    pub fn encrypt_private_key(mpass: &str, secret_key_asc: &str) -> Result<String, String> {
        let (existing_key, _headers) = SignedSecretKey::from_string(secret_key_asc)
            .map_err(|e| format!("Failed to parse secret key: {e}"))?;

        existing_key
            .verify()
            .map_err(|e| format!("Key verification failed: {e}"))?;

        let user_id = existing_key
            .details
            .users
            .first()
            .map(|u| std::str::from_utf8(u.id.id()).unwrap().to_string())
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
            .map_err(|e| format!("Failed to armor encrypted key: {e}"))
    }

    // ─── ENCRYPTION LAYER 1: AES-256-GCM session key ─────────────────────────

    /// Generates a cryptographically random 32-byte AES-256 session key.
    /// A fresh key should be generated for every password entry stored.
    ///
    /// # Returns
    /// `[u8; 32]` — 256-bit random key, suitable for AES-256-GCM
    pub fn generate_aes_session_key() -> [u8; 32] {
        let key = Aes256Gcm::generate_key(&mut AesOsRng);
        key.into()
    }

    // ─── ENCRYPTION LAYER 2: encrypt a string with AES session key ───────────

    /// Encrypts a plaintext string using AES-256-GCM with a randomly generated nonce.
    /// The output is: `[12-byte nonce] ++ [ciphertext + 16-byte GCM auth tag]`
    /// Store the entire blob — the nonce is required for decryption.
    ///
    /// # Arguments
    /// * `plaintext`    - The password/string to encrypt
    /// * `session_key`  - 32-byte AES-256 session key from `generate_aes_session_key`
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)`  - `nonce(12) ++ ciphertext(n) ++ tag(16)`
    /// * `Err(String)`  - AES-GCM error
    pub fn encrypt_string_with_aes(
        plaintext: &str,
        session_key: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let key = Key::<Aes256Gcm>::from_slice(session_key);
        let cipher = Aes256Gcm::new(key);

        // Fresh 96-bit nonce per encryption (never reuse with the same key)
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

        // Prepend nonce so decryption is self-contained
        let mut blob = nonce.to_vec(); // 12 bytes
        blob.extend_from_slice(&ciphertext); // ciphertext + 16-byte GCM tag
        Ok(blob)
    }

    // ─── ENCRYPTION LAYER 3: encrypt AES session key with PGP public key ─────

    /// Encrypts the 32-byte AES session key into a PGP PKESK message addressed
    /// to the given public key. Only the corresponding private key can recover it.
    ///
    /// # Arguments
    /// * `session_key`    - 32-byte AES session key to protect
    /// * `public_key_asc` - ASCII-armored PGP public key of the recipient
    ///
    /// # Returns
    /// * `Ok(String)`  - ASCII-armored PGP encrypted message (stores alongside the ciphertext)
    /// * `Err(String)` - Descriptive error
    pub fn encrypt_session_key_with_public_key(
        session_key: &[u8; 32],
        public_key_asc: &str,
    ) -> Result<String, String> {
        let (public_key, _) = SignedPublicKey::from_string(public_key_asc)
            .map_err(|e| format!("Failed to parse public key: {e}"))?;
    
        public_key
            .verify()
            .map_err(|e| format!("Public key verification failed: {e}"))?;
    
        // Hex-encode so payload is printable ASCII — safe inside a binary literal packet
        let hex_key: String = session_key.iter().map(|b| format!("{b:02x}")).collect();
    
        // Build raw packet bytes then deserialise into a Message
        let pkt_bytes = build_literal_packet(hex_key.as_bytes());
        let msg = Message::from_bytes(std::io::Cursor::new(pkt_bytes))
            .map_err(|e| format!("Failed to build literal message: {e}"))?;
    
        let mut rng = thread_rng();
        let encrypted = msg
            .encrypt_to_keys_seipdv1(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                &[&public_key],
            )
            .map_err(|e| format!("PKESK encryption failed: {e}"))?;
    
        encrypted
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("Armoring failed: {e}"))
    }
    // ─── DECRYPTION LAYER 1: unlock private key with master password ──────────

    /// Parses and verifies an S2K-protected ASCII-armored PGP private key.
    /// The key material stays encrypted inside `SignedSecretKey` — the master
    /// password is presented on-demand when the key is actually used (sign/decrypt).
    ///
    /// Call this first to validate `mpass` and get the key object for subsequent
    /// `decrypt_session_key_with_private_key` calls.
    ///
    /// # Arguments
    /// * `mpass`          - Master password that was used to S2K-protect this key
    /// * `secret_key_asc` - ASCII-armored PGP private key
    ///
    /// # Returns
    /// * `Ok(SignedSecretKey)` - Parsed, verified key ready for use
    /// * `Err(String)`         - Parse or verification failure
    pub fn decrypt_private_key_with_mpass(
        mpass: &str,
        secret_key_asc: &str,
    ) -> Result<SignedSecretKey, String> {
        let (secret_key, _) = SignedSecretKey::from_string(secret_key_asc)
            .map_err(|e| format!("Failed to parse secret key: {e}"))?;

        secret_key
            .verify()
            .map_err(|e| format!("Key self-signature verification failed: {e}"))?;

        // Eagerly unlock the primary key packet to validate the password now,
        // not silently fail later during decryption.
        let pw = Password::from(mpass);
        secret_key
            .primary_key
            .unlock(&pw, |_| Ok(()))
            .map_err(|e| format!("Wrong master password (S2K unlock failed): {e}"))?;

        Ok(secret_key)
    }

    // ─── DECRYPTION LAYER 2: recover AES session key with private key ─────────

    /// Decrypts a PGP PKESK-wrapped AES session key using the unlocked private key.
    ///
    /// # Arguments
    /// * `encrypted_session_key_asc` - Armored PGP message from `encrypt_session_key_with_public_key`
    /// * `secret_key`                - Unlocked `SignedSecretKey` from `decrypt_private_key_with_mpass`
    /// * `mpass`                     - Master password (required by pgp crate at decrypt time)
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - The recovered 32-byte AES session key
    /// * `Err(String)`  - Decryption or format error

    pub fn decrypt_session_key_with_private_key(
        encrypted_session_key_asc: &str,
        secret_key: &SignedSecretKey,
        mpass: &str,
    ) -> Result<[u8; 32], String> {
        let (msg, _) = Message::from_string(encrypted_session_key_asc)
            .map_err(|e| format!("Failed to parse PKESK message: {e}"))?;

        // FIX E3: Password doesn't implement Clone and decrypt() wants a Fn() -> Password,
        //         not a &Password. Capture mpass as an owned String in the closure.
        let pw_str = mpass.to_string();
        let pw_fn = || Password::from(pw_str.as_str());

        // FIX E4: decrypt() expects &[&dyn PublicKeyTrait] / &[&SignedSecretKey] — pass a
        //         plain slice, NOT &[secret_key] wrapped in an extra reference layer.
        // FIX E2: decrypt() returns Message directly, not a tuple.
        //         get_content() returns the plaintext bytes.
        let decrypted_msg = msg
            .decrypt(pw_fn, &[secret_key]) // &[&SignedSecretKey] ✓
            .map_err(|e| format!("PKESK decryption failed: {e}"))?;

        // FIX E2 continued: decrypted_msg is Message, not (Message, _).
        let content = decrypted_msg
            .get_content()
            .map_err(|e| format!("Failed to extract message content: {e}"))?
            .ok_or_else(|| "Decrypted message has no content".to_string())?;

        // Decode from hex back to 32 bytes (matching encrypt_session_key_with_public_key)
        let hex_str =
            String::from_utf8(content).map_err(|e| format!("Content is not valid UTF-8: {e}"))?;

        if hex_str.len() != 64 {
            return Err(format!(
                "Hex key has wrong length: expected 64 chars, got {}",
                hex_str.len()
            ));
        }

        let mut key = [0u8; 32];
        for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
            let byte_str =
                std::str::from_utf8(chunk).map_err(|e| format!("Invalid hex chunk: {e}"))?;
            key[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|e| format!("Hex decode failed at byte {i}: {e}"))?;
        }

        Ok(key)
    }

    // ─── DECRYPTION LAYER 3: recover plaintext string from AES ciphertext ────

    /// Decrypts an AES-256-GCM ciphertext blob back to a UTF-8 string.
    /// Expects the exact format produced by `encrypt_string_with_aes`:
    /// `[12-byte nonce] ++ [ciphertext + 16-byte GCM auth tag]`
    ///
    /// The GCM tag guarantees authenticity — any tampering returns `Err`.
    ///
    /// # Arguments
    /// * `nonce_and_ciphertext` - Blob from `encrypt_string_with_aes`
    /// * `session_key`          - The 32-byte AES key recovered via `decrypt_session_key_with_private_key`
    ///
    /// # Returns
    /// * `Ok(String)` - Recovered plaintext
    /// * `Err(String)` - Auth failure, wrong key, or bad UTF-8
    pub fn decrypt_string_with_aes(
        nonce_and_ciphertext: &[u8],
        session_key: &[u8; 32],
    ) -> Result<String, String> {
        // Minimum: 12-byte nonce + 16-byte GCM tag (empty plaintext)
        if nonce_and_ciphertext.len() < 28 {
            return Err(format!(
                "Blob too short: {} bytes (minimum 28)",
                nonce_and_ciphertext.len()
            ));
        }

        let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(12);
        let key = Key::<Aes256Gcm>::from_slice(session_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES-GCM decryption failed (wrong key or tampered data): {e}"))?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| format!("Decrypted bytes are not valid UTF-8: {e}"))
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::crypt::*;
    use pgp::composed::ArmorOptions;
    use pgp::composed::{
        Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    };
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, Password}; // FIX E5: import KeyDetails so .key_id() resolves
    use rand::thread_rng;

    const MASTER_PASS: &str = "test-master-password-123!";

    fn make_plaintext_keypair() -> (String, String) {
        let mut rng = thread_rng();
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .can_authenticate(true)
            .primary_user_id("Test <test@example.com>".into())
            .passphrase(None)
            .build()
            .expect("build params");
        let sk = params.generate(&mut rng).expect("generate");
        let pw = Password::from("");
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

    fn make_s2k_keypair() -> (String, String) {
        let (plain_sk_asc, pk_asc) = make_plaintext_keypair();
        let encrypted_sk_asc =
            encrypt_private_key(MASTER_PASS, &plain_sk_asc).expect("encrypt_private_key");
        (encrypted_sk_asc, pk_asc)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ─── generate_aes_session_key ────────────────────────────────────────────

    #[test]
    fn test_generate_aes_session_key_is_32_bytes() {
        println!("\n[TEST] test_generate_aes_session_key_is_32_bytes");
        let key = generate_aes_session_key();
        println!("  Key (hex): {}", hex_encode(&key));
        assert_eq!(key.len(), 32);
        println!("  ✓ 32-byte key confirmed");
    }

    #[test]
    fn test_generate_aes_session_key_unique_each_call() {
        println!("\n[TEST] test_generate_aes_session_key_unique_each_call");
        let a = generate_aes_session_key();
        let b = generate_aes_session_key();
        println!("  Key A: {}", hex_encode(&a));
        println!("  Key B: {}", hex_encode(&b));
        assert_ne!(a, b);
        println!("  ✓ Keys are unique");
    }

    // ─── AES encrypt / decrypt ────────────────────────────────────────────────

    #[test]
    fn test_aes_round_trip() {
        println!("\n[TEST] test_aes_round_trip");
        let key = generate_aes_session_key();
        let original = "correct-horse-battery-staple";
        let blob = encrypt_string_with_aes(original, &key).expect("encrypt");
        println!("  Blob: {} bytes", blob.len());
        let recovered = decrypt_string_with_aes(&blob, &key).expect("decrypt");
        println!("  Recovered: {recovered}");
        assert_eq!(original, recovered);
        println!("  ✓ AES round-trip ok");
    }

    #[test]
    fn test_aes_wrong_key_fails() {
        println!("\n[TEST] test_aes_wrong_key_fails");
        let key_a = generate_aes_session_key();
        let key_b = generate_aes_session_key();
        let blob = encrypt_string_with_aes("secret", &key_a).expect("encrypt");
        let result = decrypt_string_with_aes(&blob, &key_b);
        println!("  Result is Err: {}", result.is_err());
        assert!(result.is_err());
        println!("  ✓ Wrong key rejected by GCM auth tag");
    }

    #[test]
    fn test_aes_tampered_blob_fails() {
        println!("\n[TEST] test_aes_tampered_blob_fails");
        let key = generate_aes_session_key();
        let mut blob = encrypt_string_with_aes("tamper me", &key).expect("encrypt");
        blob[13] ^= 0xFF;
        let result = decrypt_string_with_aes(&blob, &key);
        assert!(result.is_err());
        println!("  ✓ Tampered ciphertext rejected");
    }

    // ─── PKESK session key encrypt / decrypt ─────────────────────────────────

    #[test]
    fn test_encrypt_session_key_returns_ok() {
        println!("\n[TEST] test_encrypt_session_key_returns_ok");
        let (_, pk_asc) = make_plaintext_keypair();
        let session_key = generate_aes_session_key();
        let result = encrypt_session_key_with_public_key(&session_key, &pk_asc);
        println!("  Result is Ok: {}", result.is_ok());
        if let Err(ref e) = result {
            println!("  Error: {e}");
        }
        assert!(result.is_ok());
        let asc = result.unwrap();
        assert!(asc.contains("BEGIN PGP MESSAGE"));
        println!("  ✓ Session key encrypted to public key");
    }

    #[test]
    fn test_session_key_pkesk_round_trip() {
        println!("\n[TEST] test_session_key_pkesk_round_trip");
        let (plain_sk_asc, pk_asc) = make_plaintext_keypair();
        let session_key = generate_aes_session_key();
        println!("  Original : {}", hex_encode(&session_key));

        let encrypted_msg = encrypt_session_key_with_public_key(&session_key, &pk_asc)
            .expect("encrypt session key");

        let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");
        let recovered = decrypt_session_key_with_private_key(&encrypted_msg, &plain_sk, "")
            .expect("decrypt session key");

        println!("  Recovered: {}", hex_encode(&recovered));
        assert_eq!(session_key, recovered);
        println!("  ✓ PKESK session key round-trip ok");
    }

    // ─── decrypt_private_key_with_mpass ──────────────────────────────────────

    #[test]
    fn test_decrypt_private_key_correct_mpass() {
        println!("\n[TEST] test_decrypt_private_key_correct_mpass");
        let (sk_asc, _) = make_s2k_keypair();
        let result = decrypt_private_key_with_mpass(MASTER_PASS, &sk_asc);
        println!("  Result is Ok: {}", result.is_ok());
        assert!(result.is_ok(), "{:?}", result.err());
        // FIX E5: KeyDetails imported above so .key_id() compiles
        println!("  Key ID: {:?}", result.unwrap().key_id());
        println!("  ✓ Private key unlocked with correct master password");
    }

    #[test]
    fn test_decrypt_private_key_wrong_mpass_fails() {
        println!("\n[TEST] test_decrypt_private_key_wrong_mpass_fails");
        let (sk_asc, _) = make_s2k_keypair();
        let result = decrypt_private_key_with_mpass("wrong-password", &sk_asc);
        println!("  Result is Err: {}", result.is_err());
        if let Err(ref e) = result {
            println!("  Error: {e}");
        }
        assert!(result.is_err());
        println!("  ✓ Wrong master password rejected");
    }

    // ─── FULL END-TO-END PIPELINE ─────────────────────────────────────────────

    #[test]
    fn test_full_hybrid_pipeline() {
        println!("\n[TEST] test_full_hybrid_pipeline");

        let password_to_store = "my-bank-password-abc123!";
        println!("  [0] Password to store       : {password_to_store}");

        // Encrypt path
        let (plain_sk_asc, pk_asc) = make_plaintext_keypair();
        let session_key = generate_aes_session_key();
        println!(
            "  [1] Session key             : {}",
            hex_encode(&session_key)
        );

        let encrypted_blob =
            encrypt_string_with_aes(password_to_store, &session_key).expect("AES encrypt");
        println!(
            "  [2] AES blob                : {} bytes",
            encrypted_blob.len()
        );

        let encrypted_sk_msg =
            encrypt_session_key_with_public_key(&session_key, &pk_asc).expect("PKESK wrap");
        println!(
            "  [3] PKESK message           : {} chars",
            encrypted_sk_msg.len()
        );

        // Decrypt path
        let (plain_sk, _) = SignedSecretKey::from_string(&plain_sk_asc).expect("parse sk");
        let recovered_session_key =
            decrypt_session_key_with_private_key(&encrypted_sk_msg, &plain_sk, "")
                .expect("PKESK unwrap");
        println!(
            "  [4] Recovered session key   : {}",
            hex_encode(&recovered_session_key)
        );

        let recovered_password =
            decrypt_string_with_aes(&encrypted_blob, &recovered_session_key).expect("AES decrypt");
        println!("  [5] Recovered password      : {recovered_password}");

        assert_eq!(session_key, recovered_session_key);
        assert_eq!(password_to_store, recovered_password);
        println!("\n  ✓ Full hybrid pipeline verified end-to-end");
    }
}
