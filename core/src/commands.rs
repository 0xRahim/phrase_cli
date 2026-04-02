pub mod Commands {

    // ─── Vault ───────────────────────────────────────────────────────────────────

    pub mod vault {
        use crate::ui;
        use crypto::crypt::keys::generate_key_pairs;
        use db::database::NewVault;
        use rpassword::read_password;
        use std::io::{self, Write};

        fn die(msg: &str) -> ! {
            ui::failure(msg);
            println!();
            std::process::exit(1);
        }

        fn open_db() -> db::database::Database {
            db::database::Database::open("/tmp/test.db")
                .unwrap_or_else(|e| die(&format!("Failed to open database: {e}")))
        }

        /// Interactively collects name, email, and a confirmed master password,
        /// returning `(user_id, mpass)` where `user_id` is `"Name <email>"`.
        pub fn prompt_vault_credentials() -> Result<(String, String), String> {
            print!("{}{}  ›  {}{}Name    {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mut name = String::new();
            io::stdin()
                .read_line(&mut name)
                .map_err(|e| format!("Failed to read name: {e}"))?;
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err("Name must not be empty".into());
            }

            print!("{}{}  ›  {}{}Email   {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
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

            print!("{}{}  ›  {}{}Master password   {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mpass = read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass.is_empty() {
                return Err("Master password must not be empty".into());
            }

            print!("{}{}  ›  {}{}Confirm password  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
            io::stdout().flush().map_err(|e| format!("Flush failed: {e}"))?;
            let mpass_confirm =
                read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass != mpass_confirm {
                return Err("Passwords do not match".into());
            }

            Ok((format!("{name} <{email}>"), mpass))
        }

        pub fn new(vname: &str) {
            ui::section(&format!("New Vault  ·  {vname}"));
            println!();

            let (user_id, mpass) = match prompt_vault_credentials() {
                Ok(creds) => creds,
                Err(e) => die(&e),
            };

            ui::info("Generating key pair…");

            let (pub_key_asc, sec_key_asc) = match generate_key_pairs(&mpass, &user_id) {
                Ok(keys) => keys,
                Err(e) => die(&format!("Key generation failed: {e}")),
            };

            let new_vault = NewVault {
                vault_name: vname.to_string(),
                public_key: pub_key_asc,
                enc_private_key: sec_key_asc,
                is_default: false,
            };

            let db = open_db();
            let vault_id = match db.create_vault(&new_vault) {
                Ok(id) => id,
                Err(e) => die(&format!("Failed to create vault: {e}")),
            };

            println!();
            ui::success("Vault created");
            ui::kv("name", vname);
            ui::kv_dim("id", &vault_id);
            println!();
        }

        pub fn list() {
            let db = open_db();
            let vaults = match db.list_vaults() {
                Ok(v) => v,
                Err(e) => die(&format!("Failed to list vaults: {e}")),
            };

            ui::section("Vaults");
            println!();

            if vaults.is_empty() {
                ui::info("No vaults found. Run `phrase vault new <name>` to create one.");
            } else {
                for v in &vaults {
                    if v.is_default {
                        ui::list_item_tagged(&v.vault_name, "default");
                    } else {
                        ui::list_item(&v.vault_name);
                    }
                }
            }
            println!();
        }

        pub fn rm(vname: &str) {
            let db = open_db();
            let vaults = match db.list_vaults() {
                Ok(v) => v,
                Err(e) => die(&format!("Failed to list vaults: {e}")),
            };

            for v in &vaults {
                if v.vault_name == vname {
                    match db.delete_vault(&v.vault_id) {
                        Ok(()) => {
                            ui::success(&format!("Vault '{vname}' deleted"));
                            println!();
                        }
                        Err(e) => die(&format!("Failed to delete vault '{vname}': {e}")),
                    }
                    return;
                }
            }

            die(&format!("Vault '{vname}' not found"));
        }

        pub fn use_(vname: &str) {
            let db = open_db();
            let vaults = match db.list_vaults() {
                Ok(v) => v,
                Err(e) => die(&format!("Failed to list vaults: {e}")),
            };

            for v in &vaults {
                if v.vault_name == vname {
                    match db.set_default_vault(v.vault_id.as_str()) {
                        Ok(()) => {
                            ui::success(&format!("Default vault set to '{vname}'"));
                            println!();
                        }
                        Err(e) => die(&format!("Failed to set default vault: {e}")),
                    }
                    return;
                }
            }

            die(&format!("Vault '{vname}' not found"));
        }
    }

    // ─── Category ────────────────────────────────────────────────────────────────

    pub mod category {
        use crate::ui;

        pub fn new(cname: &str) {
            ui::section(&format!("New Category  ·  {cname}"));
            println!();
            ui::success(&format!("Category '{cname}' created"));
            println!();
        }

        pub fn list() {
            ui::section("Categories");
            println!();
            ui::info("No categories found."); // placeholder — wire to DB when ready
            println!();
        }

        pub fn rm(cname: &str) {
            match true {
                // placeholder — replace condition with real DB call
                true => {
                    ui::success(&format!("Category '{cname}' deleted"));
                    println!();
                }
                false => {
                    ui::failure(&format!("Category '{cname}' not found"));
                    println!();
                }
            }
        }

        pub fn use_(cname: &str) {
            ui::success(&format!("Switched to category '{cname}'"));
            println!();
        }
    }

    // ─── Entry ───────────────────────────────────────────────────────────────────

    pub mod entry {
        use crate::ui;
        use arboard::Clipboard;
        use base64::{engine::general_purpose, Engine as _};
        use crypto::crypt::{
            aes::{decrypt_bytes_with_aes, encrypt_bytes_with_aes},
            decrypt_string_with_aes, encrypt_string_with_aes, generate_aes_session_key,
            // ECIES encrypt and decrypt MUST come from the same module.
            // ecies.rs uses HKDF-SHA256 as the KDF after ECDH.
            // keys.rs decrypt used raw SHA-256 — different KDF = auth tag failure.
            session_key::{
                decrypt_session_key_with_private_key, encrypt_session_key_with_public_key,
            },
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

        // ── Shared helpers ────────────────────────────────────────────────────────

        fn die(msg: &str) -> ! {
            ui::failure(msg);
            println!();
            exit(1);
        }

        fn open_db() -> db::database::Database {
            db::database::Database::open("/tmp/test.db")
                .unwrap_or_else(|e| die(&format!("Failed to open database: {e}")))
        }

        // ── Public commands ───────────────────────────────────────────────────────

        pub fn new(alias: &str, cname: &str) {
            ui::section(&format!("New Entry  ·  {alias}"));
            println!();

            let entry = collect_entry_inputs(alias, cname);
            let vault_id = current_vault_id();
            let new_entry = NewEntry {
                vault_id,
                alias: entry.alias.clone(),
                category: entry.category.clone(),
                entry_type: entry.entry_type.clone(),
                secret_data: serde_json::to_string(&entry)
                    .unwrap_or_else(|e| die(&format!("Failed to serialize entry: {e}"))),
            };

            let db = open_db();
            if let Err(e) = db.create_entry(&new_entry) {
                die(&format!("Failed to save entry '{alias}': {e}"));
            }

            println!();
            ui::success(&format!("Entry '{alias}' saved"));
            ui::kv("alias", alias);
            ui::kv("category", cname);
            println!();
        }

        pub fn list(cname: &str) {
            let db = open_db();
            let vault_id = current_vault_id();
            let entries = match db.list_entries_for_vault(&vault_id) {
                Ok(e) => e,
                Err(e) => die(&format!("Failed to list entries: {e}")),
            };

            ui::section(&format!("Entries  ·  {cname}"));
            println!();

            if entries.is_empty() {
                ui::info("No entries found. Run `phrase cred new <alias> -c <category>`.");
            } else {
                for e in &entries {
                    ui::list_item(&e.alias);
                }
            }
            println!();
        }

        pub fn rm(ename: &str, cname: &str) {
            let db = open_db();
            let entry_id = match db.get_entry_by_alias(ename) {
                Ok(e) => e.id,
                Err(_) => die(&format!("Entry '{ename}' not found")),
            };

            match db.delete_entry(entry_id.as_str()) {
                Ok(()) => {
                    ui::success(&format!("Entry '{ename}' deleted from '{cname}'"));
                    println!();
                }
                Err(e) => die(&format!("Failed to delete '{ename}': {e}")),
            }
        }

        pub fn edit(ename: &str, cname: &str) {
            ui::section(&format!("Edit Entry  ·  {ename}"));
            println!();

            let entry = collect_entry_inputs(ename, cname);
            let vault_id = current_vault_id();
            let new_entry = NewEntry {
                vault_id,
                alias: entry.alias.clone(),
                category: entry.category.clone(),
                entry_type: entry.entry_type.clone(),
                secret_data: serde_json::to_string(&entry)
                    .unwrap_or_else(|e| die(&format!("Failed to serialize entry: {e}"))),
            };

            let db = open_db();
            let id = match db.get_entry_by_alias(ename) {
                Ok(e) => e.id,
                Err(_) => die(&format!("Entry '{ename}' not found")),
            };

            match db.update_entry(
                &id,
                &new_entry.alias,
                &new_entry.category,
                &new_entry.entry_type,
                &new_entry.secret_data,
            ) {
                Ok(()) => {
                    println!();
                    ui::success(&format!("Entry '{ename}' updated"));
                    println!();
                }
                Err(e) => {
                    println!();
                    die(&format!("Failed to update '{ename}': {e}"));
                }
            }
        }

        /// Fetches and displays an entry.
        ///
        /// Prompts for the master password once here, derives the X25519 private
        /// key, then passes it into `display_entry`. This avoids re-prompting for
        /// every decryption step and keeps credential input at the command boundary.
        pub fn get(alias: &str, cname: &str) {
            ui::section(&format!("Get Entry  ·  {alias}"));
            println!();

            let db = open_db();

            print!(
                "{}{}  ›  {}{}Master password  {}",
                ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET
            );
            io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
            let mpass = read_password()
                .unwrap_or_else(|e| die(&format!("Failed to read master password: {e}")));

            ui::info("Decrypting…");
            println!();

            let vault = match db.get_default_vault() {
                Ok(v) => v,
                Err(_) => die("No default vault set. Run `phrase vault use <name>` first."),
            };

            let x25519_priv = match private_key_asc_to_x25519_bytes(&vault.enc_private_key, &mpass) {
                Ok(k) => k,
                Err(_) => die("Wrong master password or corrupted private key"),
            };

            let entry_id = match db.get_entry_by_alias(alias) {
                Ok(e) => e.id,
                Err(_) => die(&format!("Entry '{alias}' not found")),
            };

            let entry = match db.get_entry(entry_id.as_str()) {
                Ok(e) => e,
                Err(e) => die(&format!("Failed to read entry '{alias}': {e}")),
            };

            display_entry(entry, &x25519_priv);
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        fn unwrap_aes_key(blob: &[u8], x25519_priv: &[u8; 32]) -> [u8; 32] {
            match decrypt_session_key_with_private_key(blob, x25519_priv) {
                Ok(k) => k,
                Err(e) => die(&format!("Failed to decrypt AES session key: {e}")),
            }
        }

        fn wrap_aes_key(aes_key: [u8; 32]) -> Vec<u8> {
            let db = open_db();
            let vault = match db.get_default_vault() {
                Ok(v) => v,
                Err(_) => die("No default vault set. Run `phrase vault use <name>` first."),
            };
            let x25519_pub = match public_key_asc_to_x25519_bytes(&vault.public_key) {
                Ok(k) => k,
                Err(e) => die(&format!("Failed to extract public key from vault: {e}")),
            };
            match encrypt_session_key_with_public_key(&aes_key, &x25519_pub) {
                Ok(blob) => blob,
                Err(e) => die(&format!("Failed to wrap AES session key: {e}")),
            }
        }

        fn display_entry(entry: db::database::Entry, x25519_priv: &[u8; 32]) {
            let secret: Entry = match serde_json::from_str(&entry.secret_data) {
                Ok(e) => e,
                Err(e) => die(&format!("Entry data is corrupted and cannot be parsed: {e}")),
            };

            let aes_key = unwrap_aes_key(&secret.aes_key, x25519_priv);

            ui::separator();

            match entry.entry_type {
                EntryType::Login => {
                    let uname_blob = b64_decode(secret.username.as_deref().unwrap_or(""));
                    let pass_blob  = b64_decode(secret.password.as_deref().unwrap_or(""));

                    let username = match decrypt_string_with_aes(&uname_blob, &aes_key) {
                        Ok(s) => s,
                        Err(e) => die(&format!("Failed to decrypt username: {e}")),
                    };
                    let password = match decrypt_string_with_aes(&pass_blob, &aes_key) {
                        Ok(s) => s,
                        Err(e) => die(&format!("Failed to decrypt password: {e}")),
                    };

                    println!(
                        "{}  type{} {}Login{}",
                        ui::GRAY, ui::RESET, ui::BCYAN, ui::RESET
                    );
                    ui::kv("username", &username);
                    ui::kv_masked("password", "••••••••  (copied to clipboard)");

                    let cb = copy_to_clipboard(&password);
                    ui::separator();
                    println!();
                    hold_n_exit(cb);
                }

                EntryType::Note => {
                    let notes_blob = b64_decode(secret.notes.as_deref().unwrap_or(""));
                    let notes = match decrypt_string_with_aes(&notes_blob, &aes_key) {
                        Ok(s) => s,
                        Err(e) => die(&format!("Failed to decrypt note: {e}")),
                    };

                    println!(
                        "{}  type{} {}Note{}",
                        ui::GRAY, ui::RESET, ui::BCYAN, ui::RESET
                    );
                    ui::kv_masked("note", "••••••••  (copied to clipboard)");

                    let cb = copy_to_clipboard(&notes);
                    ui::separator();
                    println!();
                    hold_n_exit(cb);
                }

                EntryType::File => {
                    let enc_path = match secret.file_path {
                        Some(p) => p,
                        None => die("Entry is corrupted: missing file path"),
                    };
                    let enc_data = match std::fs::read(&enc_path) {
                        Ok(d) => d,
                        Err(e) => die(&format!("Failed to read encrypted file '{enc_path}': {e}")),
                    };
                    let dec_data = match decrypt_bytes_with_aes(&enc_data, &aes_key) {
                        Ok(d) => d,
                        Err(e) => die(&format!("Failed to decrypt file: {e}")),
                    };
                    let dec_path = enc_path.replace(".phrased", "");
                    if let Err(e) = std::fs::write(&dec_path, &dec_data) {
                        die(&format!("Failed to write decrypted file to '{dec_path}': {e}"));
                    }

                    println!(
                        "{}  type{} {}File{}",
                        ui::GRAY, ui::RESET, ui::BCYAN, ui::RESET
                    );
                    ui::kv("decrypted to", &dec_path);
                    ui::separator();
                    println!();
                }

                EntryType::Seed => {
                    let seed_blob = b64_decode(secret.seed_phrase.as_deref().unwrap_or(""));
                    let seed = match decrypt_string_with_aes(&seed_blob, &aes_key) {
                        Ok(s) => s,
                        Err(e) => die(&format!("Failed to decrypt seed phrase: {e}")),
                    };

                    println!(
                        "{}  type{} {}Seed Phrase{}",
                        ui::GRAY, ui::RESET, ui::BCYAN, ui::RESET
                    );
                    ui::kv_masked("seed", "••••••••  (copied to clipboard)");

                    let cb = copy_to_clipboard(&seed);
                    ui::separator();
                    println!();
                    hold_n_exit(cb);
                }
            }
        }

        fn collect_entry_inputs(alias: &str, cname: &str) -> Entry {
            print!(
                "{}{}  ›  {}{}Type {}{}[login / file / note / seedphrase]{}  ",
                ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET,
                ui::GRAY, ui::RESET
            );
            io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
            let mut raw = String::new();
            io::stdin()
                .read_line(&mut raw)
                .unwrap_or_else(|e| die(&format!("Failed to read entry type: {e}")));

            match raw.trim() {
                "" | "login" => {
                    print!("{}{}  ›  {}{}Username  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
                    io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
                    let mut uname = String::new();
                    io::stdin()
                        .read_line(&mut uname)
                        .unwrap_or_else(|e| die(&format!("Failed to read username: {e}")));
                    let uname = uname.trim().to_string();

                    print!("{}{}  ›  {}{}Password  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
                    io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
                    let password = read_password()
                        .unwrap_or_else(|e| die(&format!("Failed to read password: {e}")));

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
                    print!("{}{}  ›  {}{}File path  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
                    io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
                    let mut path = String::new();
                    io::stdin()
                        .read_line(&mut path)
                        .unwrap_or_else(|e| die(&format!("Failed to read file path: {e}")));
                    let path = path.trim().to_string();

                    ui::info(&format!("Reading '{path}'…"));

                    let file_data = match std::fs::read(&path) {
                        Ok(d) => d,
                        Err(e) => die(&format!("Failed to read file '{path}': {e}")),
                    };

                    ui::info("Encrypting…");

                    let aes_key = generate_aes_session_key();
                    let encrypted = match encrypt_bytes_with_aes(&file_data, &aes_key) {
                        Ok(d) => d,
                        Err(e) => die(&format!("Encryption failed: {e}")),
                    };

                    let enc_path = format!("{path}.phrased");
                    if let Err(e) = std::fs::write(&enc_path, &encrypted) {
                        die(&format!("Failed to write encrypted file to '{enc_path}': {e}"));
                    }

                    ui::kv("encrypted to", &enc_path);

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
                    print!("{}{}  ›  {}{}Note  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
                    io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
                    let note = read_password()
                        .unwrap_or_else(|e| die(&format!("Failed to read note: {e}")));

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
                    print!("{}{}  ›  {}{}Seed phrase / 2FA recovery  {}", ui::BYELLOW, ui::BOLD, ui::RESET, ui::BOLD, ui::RESET);
                    io::stdout().flush().unwrap_or_else(|e| die(&format!("Flush failed: {e}")));
                    let seed = read_password()
                        .unwrap_or_else(|e| die(&format!("Failed to read seed phrase: {e}")));

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
                    println!();
                    die(&format!("Unknown entry type '{other}'. Expected: login, file, note, seedphrase"));
                }
            }
        }

        // ── Tiny utilities ────────────────────────────────────────────────────────

        fn current_vault_id() -> String {
            let db = open_db();
            match db.get_default_vault() {
                Ok(v) => v.vault_id.to_string(),
                Err(_) => die("No default vault set. Run `phrase vault use <name>` first."),
            }
        }

        fn b64_encrypt(s: &str, aes_key: &[u8; 32]) -> String {
            let ct = match encrypt_string_with_aes(s, aes_key) {
                Ok(c) => c,
                Err(e) => die(&format!("Encryption failed: {e}")),
            };
            general_purpose::STANDARD.encode(&ct)
        }

        fn b64_decode(s: &str) -> Vec<u8> {
            match general_purpose::STANDARD.decode(s) {
                Ok(b) => b,
                Err(e) => die(&format!("Entry data is corrupted (invalid base64): {e}")),
            }
        }

        fn copy_to_clipboard(text: &str) -> Clipboard {
            let mut cb = match Clipboard::new() {
                Ok(c) => c,
                Err(e) => die(&format!("Failed to open clipboard: {e}")),
            };
            if let Err(e) = cb.set_text(text) {
                die(&format!("Failed to write to clipboard: {e}"));
            }
            // Keep the clipboard object alive by returning it.
            cb
        }

        fn hold_n_exit(mut cb: Clipboard) -> ! {
            println!(
                "{}{}  ›  {}Press Enter to clear clipboard and exit…{}",
                ui::GRAY, ui::DIM, ui::RESET, ui::RESET
            );

            let mut buf = String::new();
            io::stdin().read_line(&mut buf).ok();

            cb.clear().ok();

            exit(0);
        }
    }
}