pub mod Commands {

    // ─── Vault ───────────────────────────────────────────────────────────────────

    pub mod vault {
        use crypto::crypt::keys::generate_key_pairs;
        use db::database::NewVault;
        use rpassword::read_password;
        use std::io::{self, Write};

        /// Interactively collects name, email, and a confirmed master password,
        /// returning `(user_id, mpass)` where `user_id` is `"Name <email>"`.
        pub fn prompt_vault_credentials() -> Result<(String, String), String> {
            print!("Enter your name  : ");
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mut name = String::new();
            io::stdin()
                .read_line(&mut name)
                .map_err(|e| format!("Failed to read name: {e}"))?;
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err("Name must not be empty".into());
            }

            print!("Enter your email : ");
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mut email = String::new();
            io::stdin()
                .read_line(&mut email)
                .map_err(|e| format!("Failed to read email: {e}"))?;
            let email = email.trim().to_string();
            let at = email.find('@').ok_or("Email must contain '@'")?;
            if !email[at + 1..].contains('.') {
                return Err("Email domain must contain a '.'".into());
            }

            print!("Enter master password   : ");
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mpass = read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass.is_empty() {
                return Err("Master password must not be empty".into());
            }

            print!("Confirm master password : ");
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mpass_confirm =
                read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass != mpass_confirm {
                return Err("Passwords do not match".into());
            }

            Ok((format!("{name} <{email}>"), mpass))
        }

        pub fn new(vname: &str) {
            println!("Creating vault '{vname}'");
            let (user_id, mpass) =
                prompt_vault_credentials().expect("Failed to collect credentials");
            let (pub_key_asc, sec_key_asc) =
                generate_key_pairs(&mpass, &user_id).expect("Failed to generate keypair");

            let new_vault = NewVault {
                vault_name: vname.to_string(),
                public_key: pub_key_asc,
                enc_private_key: sec_key_asc,
                is_default: false,
            };

            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vault_id = db.create_vault(&new_vault).expect("Failed to create vault");
            println!("Vault created — id: {vault_id}");
        }

        pub fn list() {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vaults = db.list_vaults().expect("Failed to list vaults");
            if vaults.is_empty() {
                println!("No vaults found.");
            } else {
                for v in &vaults {
                    println!("[*] {}", v.vault_name);
                }
            }
        }

        pub fn rm(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vaults = db.list_vaults().expect("Failed to list vaults");
            for v in &vaults {
                if v.vault_name == vname {
                    match db.delete_vault(&v.vault_id) {
                        Ok(()) => println!("Deleted vault '{vname}'"),
                        Err(e) => println!("Failed to delete vault '{vname}': {e}"),
                    }
                    return;
                }
            }
            println!("Vault '{vname}' not found.");
        }

        pub fn use_(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vaults = db.list_vaults().expect("Failed to list vaults");
            for v in &vaults {
                if v.vault_name == vname {
                    match db.set_default_vault(v.vault_id.as_str()) {
                        Ok(()) => println!("Default vault set to '{vname}'"),
                        Err(e) => println!("Failed to set default vault: {e}"),
                    }
                    return;
                }
            }
            println!("Vault '{vname}' not found.");
        }
    }

    // ─── Category ────────────────────────────────────────────────────────────────

    pub mod category {
        pub fn new(cname: &str) {
            println!("Creating category '{cname}'");
        }
        pub fn list() {
            println!("Listing categories");
        }
        pub fn rm(cname: &str) {
            println!("Deleting category '{cname}'");
        }
        pub fn use_(cname: &str) {
            println!("Switching to category '{cname}'");
        }
    }

    // ─── Entry ───────────────────────────────────────────────────────────────────

    pub mod entry {
        use arboard::Clipboard;
        use base64::{engine::general_purpose, Engine as _};
        use crypto::crypt::{
            aes::{decrypt_bytes_with_aes, encrypt_bytes_with_aes},
            decrypt_string_with_aes, encrypt_string_with_aes, generate_aes_session_key,
            // ECIES encrypt and decrypt MUST come from the same module.
            // ecies.rs uses HKDF-SHA256 as the KDF after ECDH.
            // keys.rs decrypt used raw SHA-256 — different KDF = auth tag failure.
            session_key::{encrypt_session_key_with_public_key, decrypt_session_key_with_private_key},
            // keys: only for ASC → raw X25519 byte extraction
            keys::{private_key_asc_to_x25519_bytes, public_key_asc_to_x25519_bytes},
        };
        use db::database::{EntryType, NewEntry};
        use rpassword::read_password;
        use serde::{Deserialize, Serialize};
        use std::{
            io::{self, Write},
            process::exit,
        };

        // ── Schema ───────────────────────────────────────────────────────────────

        /// In-memory entry. All secret string fields are base64(AES-GCM ciphertext).
        /// `aes_key` is the raw AES-256 key wrapped with the vault's X25519 public key
        /// (ECIES blob: ephemeral_pub(32) | nonce(12) | ciphertext+tag).
        #[derive(Serialize, Deserialize, Debug)]
        struct Entry {
            alias: String,
            entry_type: EntryType,
            category: String,
            username: Option<String>,
            password: Option<String>,
            file_path: Option<String>,
            notes: Option<String>,
            seed_phrase: Option<String>,
            /// ECIES-wrapped AES-256 session key
            aes_key: Vec<u8>,
        }

        // ── Public commands ───────────────────────────────────────────────────────

        pub fn new(alias: &str, cname: &str) {
            println!("Creating entry '{alias}' in '{cname}'");
            let entry = collect_entry_inputs(alias, cname);
            let vault_id = current_vault_id();
            let new_entry = NewEntry {
                vault_id,
                alias: entry.alias.clone(),
                category: entry.category.clone(),
                entry_type: entry.entry_type.clone(),
                secret_data: serde_json::to_string(&entry).expect("Serialization failed"),
            };
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            db.create_entry(&new_entry).expect("Failed to create entry");
            println!("Entry '{alias}' saved.");
        }

        pub fn list(cname: &str) {
            println!("Entries in '{cname}':");
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vault_id = current_vault_id();
            let entries = db
                .list_entries_for_vault(&vault_id)
                .expect("Failed to list entries");
            for e in &entries {
                println!("  [*] {}", e.alias);
            }
        }

        pub fn rm(ename: &str, cname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let entry_id = db
                .get_entry_by_alias(ename)
                .expect("Entry not found")
                .id;
            match db.delete_entry(entry_id.as_str()) {
                Ok(()) => println!("Deleted entry '{ename}' from '{cname}'"),
                Err(e) => println!("Failed to delete '{ename}': {e}"),
            }
        }

        pub fn edit(ename: &str, cname: &str) {
            let entry = collect_entry_inputs(ename, cname);
            let vault_id = current_vault_id();
            let new_entry = NewEntry {
                vault_id,
                alias: entry.alias.clone(),
                category: entry.category.clone(),
                entry_type: entry.entry_type.clone(),
                secret_data: serde_json::to_string(&entry).expect("Serialization failed"),
            };
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let id = db.get_entry_by_alias(ename).expect("Entry not found").id;
            match db.update_entry(
                &id,
                &new_entry.alias,
                &new_entry.category,
                &new_entry.entry_type,
                &new_entry.secret_data,
            ) {
                Ok(()) => println!("Entry '{ename}' updated."),
                Err(e) => println!("Failed to update '{ename}': {e}"),
            }
        }

        /// Fetches and displays an entry.
        ///
        /// Prompts for the master password once here, derives the X25519 private
        /// key, then passes it into `display_entry`. This avoids re-prompting for
        /// every decryption step and keeps credential input at the command boundary.
        pub fn get(alias: &str, cname: &str) {
            println!("Getting entry '{alias}' from '{cname}'");

            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");

            // Prompt for master password before any decryption
            print!("Master password: ");
            io::stdout().flush().unwrap();
            let mpass = read_password().expect("Failed to read master password");

            // Derive the X25519 private scalar from the vault's PGP private key
            let vault = db.get_default_vault().expect("No default vault set");
            let x25519_priv = private_key_asc_to_x25519_bytes(&vault.enc_private_key, &mpass)
                .expect("Wrong master password or corrupted private key");

            let entry_id = db
                .get_entry_by_alias(alias)
                .expect("Entry not found")
                .id;
            let entry = db.get_entry(entry_id.as_str()).expect("Failed to read entry");

            display_entry(entry, &x25519_priv);
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        /// Decrypts the ECIES-wrapped AES session key and returns the raw 32-byte key.
        ///
        /// `blob`      — ECIES blob stored in `Entry::aes_key`
        /// `x25519_priv` — Caller-derived X25519 private scalar (from `get`)
        fn unwrap_aes_key(blob: &[u8], x25519_priv: &[u8; 32]) -> [u8; 32] {
            // Uses ecies::decrypt_session_key_with_private_key which mirrors
            // the HKDF-SHA256 KDF used on the encrypt side — must stay paired.
            decrypt_session_key_with_private_key(blob, x25519_priv)
                .expect("Failed to decrypt AES session key")
        }

        /// Encrypts a raw 32-byte AES session key with the vault's X25519 public key.
        ///
        /// Returns the ECIES blob (ephemeral_pub | nonce | ciphertext+tag).
        fn wrap_aes_key(aes_key: [u8; 32]) -> Vec<u8> {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            let vault = db.get_default_vault().expect("No default vault set");
            let x25519_pub = public_key_asc_to_x25519_bytes(&vault.public_key)
                .expect("Failed to extract X25519 public key from vault");
            encrypt_session_key_with_public_key(&aes_key, &x25519_pub)
                .expect("Failed to encrypt AES session key")
        }

        fn display_entry(entry: db::database::Entry, x25519_priv: &[u8; 32]) {
            let secret: Entry =
                serde_json::from_str(&entry.secret_data).expect("Corrupted entry data");

            // Unwrap the AES session key once — reused for every field
            let aes_key = unwrap_aes_key(&secret.aes_key, x25519_priv);

            match entry.entry_type {
                EntryType::Login => {
                    let uname_blob = b64_decode(secret.username.as_deref().unwrap_or(""));
                    let pass_blob  = b64_decode(secret.password.as_deref().unwrap_or(""));

                    let username = decrypt_string_with_aes(&uname_blob, &aes_key)
                        .expect("Failed to decrypt username");
                    let password = decrypt_string_with_aes(&pass_blob, &aes_key)
                        .expect("Failed to decrypt password");

                    println!("Username : {username}");
                    println!("Password copied to clipboard.");
                    copy_to_clipboard(&password);
                    hold_n_exit();
                }

                EntryType::Note => {
                    let notes_blob = b64_decode(secret.notes.as_deref().unwrap_or(""));
                    let notes = decrypt_string_with_aes(&notes_blob, &aes_key)
                        .expect("Failed to decrypt note");
                    copy_to_clipboard(&notes);
                    hold_n_exit();
                }

                EntryType::File => {
                    let enc_path = secret.file_path.expect("Missing file_path in entry");
                    let enc_data = std::fs::read(&enc_path).expect("Failed to read encrypted file");
                    let dec_data = decrypt_bytes_with_aes(&enc_data, &aes_key)
                        .expect("Failed to decrypt file");
                    let dec_path = enc_path.replace(".phrased", "");
                    std::fs::write(&dec_path, &dec_data).expect("Failed to write decrypted file");
                    println!("File decrypted to '{dec_path}'");
                }

                EntryType::Seed => {
                    let seed_blob = b64_decode(secret.seed_phrase.as_deref().unwrap_or(""));
                    let seed = decrypt_string_with_aes(&seed_blob, &aes_key)
                        .expect("Failed to decrypt seed phrase");
                    copy_to_clipboard(&seed);
                    hold_n_exit();
                }
            }
        }

        fn collect_entry_inputs(alias: &str, cname: &str) -> Entry {
            print!("Entry type [login / file / note / seedphrase] (default: login): ");
            io::stdout().flush().unwrap();
            let mut raw = String::new();
            io::stdin().read_line(&mut raw).expect("Failed to read input");

            match raw.trim() {
                "" | "login" => {
                    print!("Username: ");
                    io::stdout().flush().unwrap();
                    let mut uname = String::new();
                    io::stdin().read_line(&mut uname).expect("Failed to read username");
                    let uname = uname.trim().to_string();

                    print!("Password: ");
                    io::stdout().flush().unwrap();
                    let password = read_password().expect("Failed to read password");

                    let aes_key = generate_aes_session_key();
                    Entry {
                        alias: alias.into(),
                        entry_type: EntryType::Login,
                        category: cname.into(),
                        username: Some(b64_encrypt(&uname, &aes_key)),
                        password: Some(b64_encrypt(&password, &aes_key)),
                        file_path: None,
                        notes: None,
                        seed_phrase: None,
                        aes_key: wrap_aes_key(aes_key),
                    }
                }

                "file" => {
                    print!("File path: ");
                    io::stdout().flush().unwrap();
                    let mut path = String::new();
                    io::stdin().read_line(&mut path).expect("Failed to read path");
                    let path = path.trim().to_string();

                    let file_data = std::fs::read(&path).unwrap_or_else(|e| {
                        println!("Failed to read file: {e}");
                        exit(1);
                    });

                    let aes_key = generate_aes_session_key();
                    let encrypted = encrypt_bytes_with_aes(&file_data, &aes_key).unwrap_or_else(|e| {
                        println!("Encryption failed: {e}");
                        exit(1);
                    });

                    let enc_path = format!("{path}.phrased");
                    std::fs::write(&enc_path, &encrypted).expect("Failed to write encrypted file");

                    Entry {
                        alias: alias.into(),
                        entry_type: EntryType::File,
                        category: cname.into(),
                        username: None,
                        password: None,
                        file_path: Some(enc_path),
                        notes: None,
                        seed_phrase: None,
                        aes_key: wrap_aes_key(aes_key),
                    }
                }

                "note" => {
                    print!("Note: ");
                    io::stdout().flush().unwrap();
                    let note = read_password().expect("Failed to read note");

                    let aes_key = generate_aes_session_key();
                    Entry {
                        alias: alias.into(),
                        entry_type: EntryType::Note,
                        category: cname.into(),
                        username: None,
                        password: None,
                        file_path: None,
                        notes: Some(b64_encrypt(&note, &aes_key)),
                        seed_phrase: None,
                        aes_key: wrap_aes_key(aes_key),
                    }
                }

                "seedphrase" => {
                    print!("Seed phrase / 2FA recovery: ");
                    io::stdout().flush().unwrap();
                    let seed = read_password().expect("Failed to read seed phrase");

                    let aes_key = generate_aes_session_key();
                    Entry {
                        alias: alias.into(),
                        entry_type: EntryType::Seed,
                        category: cname.into(),
                        username: None,
                        password: None,
                        file_path: None,
                        notes: None,
                        seed_phrase: Some(b64_encrypt(&seed, &aes_key)),
                        aes_key: wrap_aes_key(aes_key),
                    }
                }

                other => {
                    println!("Unknown entry type '{other}'. Exiting.");
                    exit(1);
                }
            }
        }

        // ── Tiny utilities ────────────────────────────────────────────────────────

        fn current_vault_id() -> String {
            let db = db::database::Database::open("/tmp/test.db").expect("Failed to open db");
            db.get_default_vault()
                .expect("No default vault set")
                .vault_id
                .to_string()
        }

        /// `encrypt_string_with_aes(s, key)` → base64
        fn b64_encrypt(s: &str, aes_key: &[u8; 32]) -> String {
            let ct = encrypt_string_with_aes(s, aes_key).expect("AES encrypt failed");
            general_purpose::STANDARD.encode(&ct)
        }

        /// base64 → bytes (panics with a clear message on bad input)
        fn b64_decode(s: &str) -> Vec<u8> {
            general_purpose::STANDARD
                .decode(s)
                .expect("Corrupted base64 in entry")
        }

        fn copy_to_clipboard(text: &str) {
            let mut cb = Clipboard::new().expect("Failed to open clipboard");
            cb.set_text(text).expect("Failed to write to clipboard");
            
        }

        /// Wait for Enter, wipe clipboard, exit.
        fn hold_n_exit() -> ! {
            println!("Press Enter to clear clipboard and exit...");
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).unwrap();
            let mut cb = Clipboard::new().unwrap();
            cb.set_text(" ").unwrap();
            exit(0);
        }
    }
}