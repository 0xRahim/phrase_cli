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
                vault_name:      vname.to_string(),
                public_key:      pub_key_asc,
                enc_private_key: sec_key_asc,
                is_default:      false
            };
            let db = db::database::Database::open("/tmp/test.db").expect("db failed");
            let vault_id = db.create_vault(&new_vault);
            println!("Vault Id : {}",vault_id.unwrap());

        }
        pub fn list() {
            println!("Listing all vaults");
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter(){
                println!("[*] : {}",vault.vault_name);
            }

            
        }
        pub fn rm(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter(){
                if vault.vault_name == vname {
                    if let Ok(()) = db.delete_vault(&vault.vault_id){
                        println!("Deleted Vault {} ", vault.vault_name);
                    }
                    else {
                        println!("Error While Deleting : {}",vault.vault_name);
                    }
                }
            }

        }
        pub fn use_(vname: &str) {
            let db = db::database::Database::open("/tmp/test.db").expect("b failed");
            let vaults = db.list_vaults();
            for vault in vaults.unwrap().iter(){
                if vault.vault_name == vname {
                    if let Ok(()) = db.set_default_vault(vault.vault_id.as_str()){
                        println!("Default Vault : {} ", vault.vault_name);
                    }
                    else {
                        println!("Error While Setting Default : {}",vault.vault_name);
                    }
                }
            }

        }
    }
    pub mod category {
        pub fn new(cname: &str) {
            println!("Creating a new category {} ", cname);
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
        pub fn new(ename: &str, cname: &str) {
            println!("Creating a new entry {} in category {} ", ename, cname);
        }
        pub fn list(cname: &str) {
            println!("Listing all entries in category {} ", cname);
        }
        pub fn rm(ename: &str, cname: &str) {
            println!("Deleting Entry {} in category {} ", ename, cname);
        }
        pub fn edit(ename: &str, cname: &str) {
            println!("Switching To Entry {} in category {} ", ename, cname);
        }
        pub fn get(ename: &str, cname: &str) {
            println!("Getting Entry {} in category {} ", ename, cname);
        }
    }
}
