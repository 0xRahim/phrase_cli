/// Integration tests – use a real temporary file-backed SQLite database
/// (via `tempfile`) so they exercise the full I/O path including WAL mode,
/// foreign-key enforcement, and on-disk persistence within a single test run.
#[cfg(test)]
mod integration_tests {
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    use crate::database::{Database, DbError, EntryType, NewEntry, NewVault};

    // ── Fixture ───────────────────────────────────────────────────────────────

    struct Fixture {
        /// Keep the NamedTempFile alive so the file isn't deleted mid-test.
        _tmp:  NamedTempFile,
        db:    Database,
        pub path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp  = NamedTempFile::new().expect("could not create temp file");
            let path = tmp.path().to_path_buf();
            let db   = Database::open(path.to_str().unwrap()).expect("failed to open db");
            Fixture { _tmp: tmp, db, path }
        }
    }

    fn make_vault(name: &str) -> NewVault {
        NewVault {
            vault_name:      name.to_owned(),
            public_key:      format!("pub_{name}"),
            enc_private_key: format!("enc_{name}"),
        }
    }

    fn make_entry(vault_id: &str, alias: &str, entry_type: EntryType, secret: &str) -> NewEntry {
        NewEntry {
            vault_id:    vault_id.to_owned(),
            alias:       alias.to_owned(),
            category:    "General".to_owned(),
            entry_type,
            secret_data: secret.to_owned(),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Full VAULT lifecycle
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_vault_full_lifecycle() {
        let f = Fixture::new();

        // CREATE
        let id = f.db.create_vault(&make_vault("MyVault")).unwrap();
        assert!(!id.is_empty());

        // READ
        let v = f.db.get_vault(&id).unwrap();
        assert_eq!(v.vault_name, "MyVault");

        // LIST contains our vault
        let list = f.db.list_vaults().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].vault_id, id);

        // UPDATE
        f.db.update_vault(&id, "RenamedVault", "new_pub", "new_enc").unwrap();
        let updated = f.db.get_vault(&id).unwrap();
        assert_eq!(updated.vault_name, "RenamedVault");

        // DELETE
        f.db.delete_vault(&id).unwrap();
        let list_after = f.db.list_vaults().unwrap();
        assert!(list_after.is_empty());

        // Double-delete → NotFound
        let err = f.db.delete_vault(&id).unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn integration_vault_unique_name_constraint() {
        let f = Fixture::new();
        f.db.create_vault(&make_vault("Unique")).unwrap();
        // Duplicate vault_name should fail at the DB level
        let err = f.db.create_vault(&make_vault("Unique")).unwrap_err();
        assert!(matches!(err, DbError::Rusqlite(_)));
    }

    #[test]
    fn integration_list_vaults_ordered_alphabetically() {
        let f = Fixture::new();
        for name in &["Zebra", "Apple", "Mango"] {
            f.db.create_vault(&make_vault(name)).unwrap();
        }
        let names: Vec<_> = f.db
            .list_vaults()
            .unwrap()
            .into_iter()
            .map(|v| v.vault_name)
            .collect();
        assert_eq!(names, vec!["Apple", "Mango", "Zebra"]);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Full ENTRY lifecycle
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_entry_full_lifecycle() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("Vault1")).unwrap();

        // CREATE
        let secret = r#"{"user":"alice","pass":"hunter2"}"#;
        let eid = f.db.create_entry(&make_entry(&vid, "GitHub", EntryType::Login, secret)).unwrap();

        // READ
        let e = f.db.get_entry(&eid).unwrap();
        assert_eq!(e.alias,       "GitHub");
        assert_eq!(e.entry_type,  EntryType::Login);
        assert_eq!(e.secret_data, secret);
        assert_eq!(e.vault_id,    vid);

        // LIST for vault
        let entries = f.db.list_entries_for_vault(&vid).unwrap();
        assert_eq!(entries.len(), 1);

        // UPDATE
        f.db.update_entry(
            &eid,
            "GitLab",
            "Work",
            &EntryType::Login,
            r#"{"user":"alice","pass":"n3wPass!"}"#,
        ).unwrap();
        let updated = f.db.get_entry(&eid).unwrap();
        assert_eq!(updated.alias,       "GitLab");
        assert_eq!(updated.secret_data, r#"{"user":"alice","pass":"n3wPass!"}"#);

        // DELETE
        f.db.delete_entry(&eid).unwrap();
        assert!(f.db.get_entry(&eid).is_err());

        // LIST is empty again
        assert!(f.db.list_entries_for_vault(&vid).unwrap().is_empty());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Cross-vault isolation
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_entries_isolated_per_vault() {
        let f    = Fixture::new();
        let vid1 = f.db.create_vault(&make_vault("VaultA")).unwrap();
        let vid2 = f.db.create_vault(&make_vault("VaultB")).unwrap();

        // Add 2 entries to vault1, 1 to vault2
        f.db.create_entry(&make_entry(&vid1, "Entry-A1", EntryType::Login,  "{}")).unwrap();
        f.db.create_entry(&make_entry(&vid1, "Entry-A2", EntryType::Note,   "{}")).unwrap();
        f.db.create_entry(&make_entry(&vid2, "Entry-B1", EntryType::Seed,   "{}")).unwrap();

        assert_eq!(f.db.list_entries_for_vault(&vid1).unwrap().len(), 2);
        assert_eq!(f.db.list_entries_for_vault(&vid2).unwrap().len(), 1);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Cascade DELETE
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_delete_vault_cascades_entries() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("CascadeVault")).unwrap();

        let eid1 = f.db.create_entry(&make_entry(&vid, "E1", EntryType::Login, "{}")).unwrap();
        let eid2 = f.db.create_entry(&make_entry(&vid, "E2", EntryType::Note,  "{}")).unwrap();

        // Delete parent vault
        f.db.delete_vault(&vid).unwrap();

        // Both child entries must be gone
        assert!(matches!(f.db.get_entry(&eid1).unwrap_err(), DbError::NotFound(_)));
        assert!(matches!(f.db.get_entry(&eid2).unwrap_err(), DbError::NotFound(_)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Foreign key enforcement – entry without valid vault
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_entry_rejects_orphan_vault_id() {
        let f   = Fixture::new();
        let err = f.db
            .create_entry(&make_entry("00000000-0000-0000-0000-000000000000", "X", EntryType::Login, "{}"))
            .unwrap_err();
        // Our own get_vault check returns NotFound before even hitting SQLite
        assert!(matches!(err, DbError::NotFound(_)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  list_entries_by_type – mixed entry types
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_list_entries_by_type_all_variants() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("TypeVault")).unwrap();

        let types = vec![
            (EntryType::Login, r#"{"user":"u","pass":"p"}"#),
            (EntryType::Note,  r#"{"note":"secret note"}"#),
            (EntryType::File,  r#"{"path":"/vault/f.key","size":"1kb"}"#),
            (EntryType::Seed,  r#"{"phrase":"word1 word2 word3"}"#),
        ];

        for (i, (et, secret)) in types.iter().enumerate() {
            f.db.create_entry(&make_entry(&vid, &format!("alias-{i}"), et.clone(), secret)).unwrap();
        }

        assert_eq!(f.db.list_entries_by_type(&vid, &EntryType::Login).unwrap().len(), 1);
        assert_eq!(f.db.list_entries_by_type(&vid, &EntryType::Note ).unwrap().len(), 1);
        assert_eq!(f.db.list_entries_by_type(&vid, &EntryType::File ).unwrap().len(), 1);
        assert_eq!(f.db.list_entries_by_type(&vid, &EntryType::Seed ).unwrap().len(), 1);

        // Total in vault
        assert_eq!(f.db.list_entries_for_vault(&vid).unwrap().len(), 4);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Persistence across two Database handles on the same file
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_data_persists_across_connections() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("PersistVault")).unwrap();
        f.db.create_entry(&make_entry(&vid, "PersistEntry", EntryType::Login, r#"{"k":"v"}"#)).unwrap();

        // Open a second connection to the same file
        let db2 = Database::open(f.path.to_str().unwrap()).unwrap();
        let vaults  = db2.list_vaults().unwrap();
        let entries = db2.list_entries_for_vault(&vid).unwrap();
        assert_eq!(vaults.len(),  1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "PersistEntry");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Seed phrase entry round-trip (multi-word sensitive secret)
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_seed_phrase_entry_round_trip() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("SeedVault")).unwrap();
        let phrase = "apple banana cherry date elderberry fig grape hawthorn iris jasmine kiwi lemon";
        let secret = format!(r#"{{"phrase":"{phrase}"}}"#);
        let eid = f.db.create_entry(&make_entry(&vid, "MainWallet", EntryType::Seed, &secret)).unwrap();

        let e = f.db.get_entry(&eid).unwrap();
        assert_eq!(e.entry_type, EntryType::Seed);
        assert!(e.secret_data.contains(phrase));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  File entry round-trip
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_file_entry_round_trip() {
        let f   = Fixture::new();
        let vid = f.db.create_vault(&make_vault("FileVault")).unwrap();
        let secret = r#"{"path":"/storage/vault1/private.key","size":"4kb"}"#;
        let eid = f.db.create_entry(&make_entry(&vid, "SSH Key", EntryType::File, secret)).unwrap();

        let e = f.db.get_entry(&eid).unwrap();
        assert_eq!(e.entry_type, EntryType::File);
        assert!(e.secret_data.contains("/storage/vault1/private.key"));
    }
}