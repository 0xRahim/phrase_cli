/*
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/

// LIBRARIES TO USE iii(https://crates.io/crates/pgp )
// GET MASTER PASSWORD FROM USER
// GENERATE PRIVATE KEY AND PUBLIC KEY USING (SecretKeyParamsBuilder)
// GENERATE ENCRYPED PRIVATE KEY USING MASTER PASSWORD (StringToKey or S2K)
// STORE METADATA SALT AND STUFF
//
//
// // Generate a random session key for AES-256
//   let session_key = PlainSessionKey::generate(&mut rng, SymmetricKeyAlgorithm::AES256);
// ENCRYPT YOUR PASSWORD WITH THE SESSION KEY
// ENCRYPT YOUR AES SESSION KEY WITH (PUBLIC KEY)
pub mod crypt {
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey};
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, Password};
    use pgp::composed::ArmorOptions;
    use rand::thread_rng;

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

        // Export secret key as .asc (ASCII armored)
        let secret_key_asc = signed_secret_key
            .to_armored_string(ArmorOptions::default())
            .expect("Failed to armor secret key");

        // Export public key as .asc (ASCII armored)
        let public_key_asc = signed_public_key
            .to_armored_string(ArmorOptions::default())
            .expect("Failed to armor public key");

        println!("=== KEY INFO ===");
        println!("Key ID:      {:?}", signed_public_key.key_id());
        println!("Fingerprint: {}", fingerprint);

        println!("\n=== SECRET KEY ===");
        println!("{}", secret_key_asc);

        println!("=== PUBLIC KEY ===");
        println!("{}", public_key_asc);
    }
}