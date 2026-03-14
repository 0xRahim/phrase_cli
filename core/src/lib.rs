pub mod Commands {

    pub mod vault {
        use crypto::crypt::generate_key_pairs;
        use db::database::NewVault;
        use rpassword::read_password;
        use std::io::{self, Write};

        /// Collects vault identity and master password from the user interactively.
        ///
        /// Prompts for:
        ///   - Display name  (e.g. "Alice")
        ///   - Email address (e.g. "alice@example.com")
        ///   - Master password (hidden input — not echoed to terminal)
        ///
        /// Returns `Ok((user_id, master_password))` where user_id is `"Name <email>"`.
        pub fn prompt_vault_credentials() -> Result<(String, String), String> {
            // ── name ──────────────────────────────────────────────────────────────────
            print!("Enter your name  : ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Flush failed: {e}"))?;
            let mut name = String::new();
            io::stdin()
                .read_line(&mut name)
                .map_err(|e| format!("Failed to read name: {e}"))?;
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err("Name must not be empty".to_string());
            }

            // ── email ─────────────────────────────────────────────────────────────────
            print!("Enter your email : ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Flush failed: {e}"))?;
            let mut email = String::new();
            io::stdin()
                .read_line(&mut email)
                .map_err(|e| format!("Failed to read email: {e}"))?;
            let email = email.trim().to_string();

            // Basic sanity check — not full RFC 5322, just catches obvious mistakes
            let at = email.find('@').ok_or("Email must contain '@'")?;
            if !email[at + 1..].contains('.') {
                return Err("Email domain must contain a '.'".to_string());
            }

            // ── master password (hidden) ───────────────────────────────────────────────
            print!("Enter master password: ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Flush failed: {e}"))?;
            let mpass = read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass.is_empty() {
                return Err("Master password must not be empty".to_string());
            }

            // ── confirm password ──────────────────────────────────────────────────────
            print!("Confirm master password: ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Flush failed: {e}"))?;
            let mpass_confirm =
                read_password().map_err(|e| format!("Failed to read password: {e}"))?;
            if mpass != mpass_confirm {
                return Err("Passwords do not match".to_string());
            }

            let user_id = format!("{name} <{email}>");
            Ok((user_id, mpass))
        }
        pub fn new(vname: &str) {
            println!("Creating a new vault {} ", vname);
            let (user_id, mpass) =
                prompt_vault_credentials().expect("Failed to collect credentials");
            let (pub_key_asc, sec_key_asc) =
                generate_key_pairs(&mpass, &user_id).expect("Failed to generate keypair");
            println!("Public Key : {pub_key_asc}");
            println!("Secret Key : {sec_key_asc}");

            // let secret_key_raw = decrypt_private_key_with_mpass(&mpass, &sec_key_asc).expect("can not decrypt private key");
            // Storing in the db

            let new_vault = NewVault {
                vault_name: vname.to_string(),
                public_key: pub_key_asc,
                enc_private_key: sec_key_asc,
                is_default: false,
            };
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let vault_id = db.create_vault(&new_vault);
            println!("Vault Id : {}", vault_id.unwrap());
        }
        pub fn list() {
            println!("Listing all vaults");
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter() {
                println!("[*] : {}", vault.vault_name);
            }
        }
        pub fn rm(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter() {
                if vault.vault_name == vname {
                    if let Ok(()) = db.delete_vault(&vault.vault_id) {
                        println!("Deleted Vault {} ", vault.vault_name);
                    } else {
                        println!("Error While Deleting : {}", vault.vault_name);
                    }
                }
            }
        }
        pub fn use_(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter() {
                if vault.vault_name == vname {
                    if let Ok(()) = db.set_default_vault(vault.vault_id.as_str()) {
                        println!("Default Vault : {} ", vault.vault_name);
                    } else {
                        println!("Error While Setting Default : {}", vault.vault_name);
                    }
                }
            }
        }
    }
    pub mod category {
        pub fn new(cname: &str) {
            println!(
                "Creating a new category and adding a new entry to it {} ",
                cname
            );
        }
        pub fn list() {
            println!("Listing all categories");
        }
        pub fn rm(cname: &str) {
            println!("Deleting Category {} ", cname);
        }
        pub fn use_(cname: &str) {
            println!("Switching To Category {} ", cname);
        }
    }
    pub mod entry {
        use crypto::crypt::generate_aes_session_key;
        use db::database::{EntryType, NewEntry};
        use serde::{Serialize,Deserialize};
        use std::{io, process::exit};
        use std::io::{Write};
        use crypto::crypt::encrypt_string_with_aes;
        use base64::{engine::general_purpose, Engine as _};
        use crypto::crypt::decrypt_string_with_aes;
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
            aes_key: [u8; 32],
        }
        pub fn new(alias: &str, cname: &str) {
            println!("Creating a new entry {} in category {} ", alias, cname);
            let entry = get_entry_inputs(alias, cname);
            let vault_id = get_current_vault_id();
            let data = serde_json::to_string(&entry).unwrap();
            let new_entry = NewEntry {
                vault_id: vault_id,
                alias: entry.alias,
                category: entry.category,
                entry_type: entry.entry_type,
                secret_data: data,
            };
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            db.create_entry(&new_entry).expect("Error");
        }
        pub fn list(cname: &str) {
            println!("Listing all entries in category {} ", cname);
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let vault_id = get_current_vault_id();
            // TODO : Add category filter and make it work
            let entries = db.list_entries_for_vault(&vault_id);
            for entry in entries.unwrap().iter() {
                println!("[*] : {}", entry.alias);
            }
        }
        pub fn rm(ename: &str, cname: &str) {
            println!("Deleting Entry {} in category {} ", ename, cname);
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let entry = db.get_entry_by_alias(ename);
            let entry_id = entry.unwrap().id;
            if let Ok(()) = db.delete_entry(entry_id.as_str()){
                println!("Deleted {} ",ename)
            }
            else {
                println!("Failed in deleting ... ")
            }
        }
        pub fn edit(ename: &str, cname: &str) {
            println!("Switching To Entry {} in category {} ", ename, cname);
            let entry = get_entry_inputs(ename, cname);
            let vault_id = get_current_vault_id();
            let data = serde_json::to_string(&entry).unwrap();
            let new_entry = NewEntry {
                vault_id: vault_id,
                alias: entry.alias,
                category: entry.category,
                entry_type: entry.entry_type,
                secret_data: data,
            };
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let id = db.get_entry_by_alias(&ename).unwrap().id;
            if let Ok(()) = db.update_entry(&id, &new_entry.alias, &new_entry.category, &new_entry.entry_type, &new_entry.secret_data){
                println!("Entry Updated");
            }else {
                println!("Failed to update the entry");
            }

        }
        pub fn get(alias: &str, cname: &str) {
            println!("Getting Entry {} in category {} ", alias, cname);
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let entry_id = db.get_entry_by_alias(alias).expect("failed to read entry by alias").id;
            let data = db.get_entry(entry_id.as_str()).expect("Failed to read entry");
            display_entry(data);

        }

        // HELPER FUNCTIONS ----------------------------------
        // ---------------------------------------------------
       fn display_entry(entry: db::database::Entry){
        let secret_data_struct: self::Entry= serde_json::from_str(&entry.secret_data).unwrap();
        match entry.entry_type{
            
            EntryType::Login => {
                let username_blob: Vec<u8> = general_purpose::STANDARD
    .decode(secret_data_struct.username.unwrap())
    .map_err(|e| format!("Base64 decode failed: {e}")).unwrap();

                let password_blob: Vec<u8> = general_purpose::STANDARD
    .decode(secret_data_struct.password.unwrap())
    .map_err(|e| format!("Base64 decode failed: {e}")).unwrap();
                let password = decrypt_string_with_aes(&password_blob, &secret_data_struct.aes_key).unwrap();
                let username = decrypt_string_with_aes(&username_blob, &secret_data_struct.aes_key).unwrap();
                println!("Username : {}", username);
                println!("Password : {}", password);
                
            }
            EntryType::Note => {
                println!("Implement later");
            }
            EntryType::File => {
                println!("Implement later");
            }
            EntryType::Seed => {
                println!("Implement later");
            }
        }
       }

        fn get_entry_inputs(alias: &str, cname: &str) -> Entry {
            // Ask for entry type
            print!("Entry Type [default=login]: login, file, note, seedphrase: ");
            io::stdout().flush().unwrap();

            let mut entry_type = String::new();
            io::stdin()
                .read_line(&mut entry_type)
                .expect("Error reading input");

            let entry_type = entry_type.trim(); // remove newline and spaces

            match entry_type {
                "" | "login" => {
                    // Ask for username
                    print!("Enter Username: ");
                    io::stdout().flush().unwrap();
                    let mut username = String::new();
                    io::stdin()
                        .read_line(&mut username)
                        .expect("Error reading username");
                    let username = username.trim().to_string();

                    // Ask for password
                    print!("Enter Password: ");
                    io::stdout().flush().unwrap();
                    let password = rpassword::read_password().expect("Failed to read password");
                    let aes_key = generate_aes_session_key();
                    let key_w_pass = encrypt_string_with_aes(password.as_str(), &aes_key).unwrap();
                    let key_w_uname = encrypt_string_with_aes(username.as_str(), &aes_key).unwrap();
                    let password = general_purpose::STANDARD.encode(&key_w_pass);
                    let username = general_purpose::STANDARD.encode(&key_w_uname);
                    Entry {
                        alias: alias.to_string(),
                        entry_type: EntryType::Login,
                        category: cname.to_string(),
                        username: Some(username),
                        password: Some(password),
                        file_path: None,
                        notes: None,
                        seed_phrase: None,
                        aes_key: aes_key,
                    }
                }
                /*
                "file" => {
                    // implement file type input
                }
                "note" => {
                    // implement note type input
                }
                "seedphrase" => {
                    // implement seedphrase input
                }
                */
                _ => {
                    println!("Invalid type entered. Exiting.");
                    exit(1);
                }
            }
        }
        fn get_current_vault_id() -> String {
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let vault = db.get_default_vault().expect("can't get default vault");
            return vault.vault_id.to_string();
        }
    }
}
