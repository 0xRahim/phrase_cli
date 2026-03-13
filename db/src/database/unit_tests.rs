/// Unit tests – each test gets its own in-memory database so they are fully
/// isolated and require no filesystem access.
#[cfg(test)]
mod unit_tests {
    use crate::database::{Database, DbError, EntryType, NewEntry, NewVault};
   

    // ── helpers ───────────────────────────────────────────────────────────────

    fn in_memory_db() -> Database {
        Database::open(":memory:").expect("in-memory db failed")
    }

    fn sample_vault() -> NewVault {
        NewVault {
            vault_name:      "TestVault".into(),
            public_key:      "pub_key_abc123".into(),
            enc_private_key: "enc_priv_xyz789".into(),
            is_default:      false,
        }
    }

    fn sample_entry(vault_id: &str) -> NewEntry {
        NewEntry {
            vault_id:    vault_id.to_owned(),
            alias:       "Gmail".into(),
            category:    "Work".into(),
            entry_type:  EntryType::Login,
            secret_data: r#"{"user":"admin","pass":"s3cr3t"}"#.into(),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  VAULT – unit
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_create_vault_returns_uuid() {
        let db = in_memory_db();
        let id = db.create_vault(&sample_vault()).unwrap();
        assert!(!id.is_empty(), "vault_id should not be empty");
        // Must parse as a valid UUID
        uuid::Uuid::parse_str(&id).expect("should be a valid UUID");
    }

    #[test]
    fn test_create_vault_empty_name_fails() {
        let db = in_memory_db();
        let bad = NewVault { vault_name: "  ".into(), ..sample_vault() };
        let err = db.create_vault(&bad).unwrap_err();
        assert!(matches!(err, DbError::InvalidInput(_)));
    }

    #[test]
    fn test_get_vault_round_trip() {
        let db  = in_memory_db();
        let id  = db.create_vault(&sample_vault()).unwrap();
        let v   = db.get_vault(&id).unwrap();
        assert_eq!(v.vault_id,        id);
        assert_eq!(v.vault_name,      "TestVault");
        assert_eq!(v.public_key,      "pub_key_abc123");
        assert_eq!(v.enc_private_key, "enc_priv_xyz789");
    }

    #[test]
    fn test_get_vault_not_found() {
        let db  = in_memory_db();
        let err = db.get_vault("non-existent-id").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_list_vaults_empty() {
        let db    = in_memory_db();
        let vaults = db.list_vaults().unwrap();
        assert!(vaults.is_empty());
    }

    #[test]
    fn test_list_vaults_multiple() {
        let db = in_memory_db();
        for name in &["Alpha", "Beta", "Gamma"] {
            db.create_vault(&NewVault {
                vault_name: (*name).into(),
                ..sample_vault()
            }).unwrap();
        }
        let vaults = db.list_vaults().unwrap();
        assert_eq!(vaults.len(), 3);
        // Results should be alphabetically ordered by vault_name
        let names: Vec<_> = vaults.iter().map(|v| v.vault_name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Beta", "Gamma"]);
    }

    #[test]
    fn test_update_vault_success() {
        let db = in_memory_db();
        let id = db.create_vault(&sample_vault()).unwrap();
        db.update_vault(&id, "UpdatedName", "new_pub", "new_enc", false).unwrap();
        let v = db.get_vault(&id).unwrap();
        assert_eq!(v.vault_name,      "UpdatedName");
        assert_eq!(v.public_key,      "new_pub");
        assert_eq!(v.enc_private_key, "new_enc");
    }

    #[test]
    fn test_update_vault_empty_name_fails() {
        let db = in_memory_db();
        let id = db.create_vault(&sample_vault()).unwrap();
        let err = db.update_vault(&id, "", "pk", "epk",false).unwrap_err();
        assert!(matches!(err, DbError::InvalidInput(_)));
    }

    #[test]
    fn test_update_vault_not_found() {
        let db  = in_memory_db();
        let err = db.update_vault("ghost", "n", "p", "e",false).unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_delete_vault_success() {
        let db  = in_memory_db();
        let id  = db.create_vault(&sample_vault()).unwrap();
        db.delete_vault(&id).unwrap();
        assert!(db.get_vault(&id).is_err());
    }

    #[test]
    fn test_delete_vault_not_found() {
        let db  = in_memory_db();
        let err = db.delete_vault("ghost").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  ENTRY – unit
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_create_entry_returns_uuid() {
        let db = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let eid = db.create_entry(&sample_entry(&vid)).unwrap();
        uuid::Uuid::parse_str(&eid).expect("should be a valid UUID");
    }

    #[test]
    fn test_create_entry_invalid_vault_fails() {
        let db  = in_memory_db();
        let err = db.create_entry(&sample_entry("bad-vault-id")).unwrap_err();
        // Parent vault not found
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_create_entry_empty_alias_fails() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let bad = NewEntry { alias: "".into(), ..sample_entry(&vid) };
        let err = db.create_entry(&bad).unwrap_err();
        assert!(matches!(err, DbError::InvalidInput(_)));
    }

    #[test]
    fn test_get_entry_round_trip() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let eid = db.create_entry(&sample_entry(&vid)).unwrap();
        let e   = db.get_entry(&eid).unwrap();
        assert_eq!(e.id,          eid);
        assert_eq!(e.vault_id,    vid);
        assert_eq!(e.alias,       "Gmail");
        assert_eq!(e.category,    "Work");
        assert_eq!(e.entry_type,  EntryType::Login);
        assert_eq!(e.secret_data, r#"{"user":"admin","pass":"s3cr3t"}"#);
    }

    #[test]
    fn test_get_entry_not_found() {
        let db  = in_memory_db();
        let err = db.get_entry("no-such-id").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_list_entries_for_vault_empty() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let entries = db.list_entries_for_vault(&vid).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entries_for_vault_multiple() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        for alias in &["GitHub", "AWS", "Notion"] {
            db.create_entry(&NewEntry { alias: (*alias).into(), ..sample_entry(&vid) }).unwrap();
        }
        let entries = db.list_entries_for_vault(&vid).unwrap();
        assert_eq!(entries.len(), 3);
        // Should be alphabetically ordered
        let aliases: Vec<_> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, vec!["AWS", "GitHub", "Notion"]);
    }

    #[test]
    fn test_list_entries_by_type() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        db.create_entry(&NewEntry {
            alias:      "Login1".into(),
            entry_type: EntryType::Login,
            ..sample_entry(&vid)
        }).unwrap();
        db.create_entry(&NewEntry {
            alias:      "Seed1".into(),
            entry_type: EntryType::Seed,
            secret_data: r#"{"phrase":"apple banana cherry"}"#.into(),
            ..sample_entry(&vid)
        }).unwrap();

        let logins = db.list_entries_by_type(&vid, &EntryType::Login).unwrap();
        let seeds  = db.list_entries_by_type(&vid, &EntryType::Seed).unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(seeds.len(),  1);
        assert_eq!(logins[0].alias, "Login1");
        assert_eq!(seeds[0].alias,  "Seed1");
    }

    #[test]
    fn test_update_entry_success() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let eid = db.create_entry(&sample_entry(&vid)).unwrap();

        db.update_entry(
            &eid,
            "NewAlias",
            "Personal",
            &EntryType::Note,
            r#"{"note":"updated"}"#,
        ).unwrap();

        let e = db.get_entry(&eid).unwrap();
        assert_eq!(e.alias,       "NewAlias");
        assert_eq!(e.category,    "Personal");
        assert_eq!(e.entry_type,  EntryType::Note);
        assert_eq!(e.secret_data, r#"{"note":"updated"}"#);
        // vault linkage must not change
        assert_eq!(e.vault_id, vid);
    }

    #[test]
    fn test_update_entry_empty_alias_fails() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let eid = db.create_entry(&sample_entry(&vid)).unwrap();
        let err = db.update_entry(&eid, "  ", "Personal", &EntryType::Note, "{}").unwrap_err();
        assert!(matches!(err, DbError::InvalidInput(_)));
    }

    #[test]
    fn test_update_entry_not_found() {
        let db  = in_memory_db();
        let err = db.update_entry("ghost", "A", "B", &EntryType::Note, "{}").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_delete_entry_success() {
        let db  = in_memory_db();
        let vid = db.create_vault(&sample_vault()).unwrap();
        let eid = db.create_entry(&sample_entry(&vid)).unwrap();
        db.delete_entry(&eid).unwrap();
        assert!(db.get_entry(&eid).is_err());
    }

    #[test]
    fn test_delete_entry_not_found() {
        let db  = in_memory_db();
        let err = db.delete_entry("ghost").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  EntryType helpers – unit
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_entry_type_from_str_all_variants() {
        for (s, expected) in &[
            ("LOGIN", EntryType::Login),
            ("login", EntryType::Login),
            ("NOTE",  EntryType::Note),
            ("FILE",  EntryType::File),
            ("SEED",  EntryType::Seed),
        ] {
            assert_eq!(EntryType::from_str(s).unwrap(), *expected);
        }
    }

    #[test]
    fn test_entry_type_from_str_invalid() {
        let err = EntryType::from_str("UNKNOWN").unwrap_err();
        assert!(matches!(err, DbError::InvalidInput(_)));
    }

    #[test]
    fn test_entry_type_display() {
        assert_eq!(EntryType::Login.to_string(), "LOGIN");
        assert_eq!(EntryType::Note.to_string(),  "NOTE");
        assert_eq!(EntryType::File.to_string(),  "FILE");
        assert_eq!(EntryType::Seed.to_string(),  "SEED");
    }



    // ══ IS_DEFAULT / default vault – unit ══

    #[test]
    fn test_create_vault_is_default_false_by_default() {
        let db = in_memory_db();
        let id = db.create_vault(&sample_vault()).unwrap(); // is_default: false
        let v  = db.get_vault(&id).unwrap();
        assert_eq!(v.is_default, false);
    }

    #[test]
    fn test_get_default_vault_none_set() {
        let db  = in_memory_db();
        let err = db.get_default_vault().unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_create_vault_as_default() {
        let db = in_memory_db();
        let id = db.create_vault(&NewVault { is_default: true, ..sample_vault() }).unwrap();
        let v  = db.get_default_vault().unwrap();
        assert_eq!(v.vault_id,   id);
        assert_eq!(v.is_default, true);
    }

    #[test]
    fn test_only_one_default_on_create() {
        let db  = in_memory_db();
        let id1 = db.create_vault(&NewVault { vault_name: "V1".into(), is_default: true,  ..sample_vault() }).unwrap();
        let id2 = db.create_vault(&NewVault { vault_name: "V2".into(), is_default: true,  ..sample_vault() }).unwrap();
        // id1 must now be non-default
        assert_eq!(db.get_vault(&id1).unwrap().is_default, false);
        assert_eq!(db.get_vault(&id2).unwrap().is_default, true);
        // Only one default returned
        assert_eq!(db.get_default_vault().unwrap().vault_id, id2);
    }

    #[test]
    fn test_set_default_vault() {
        let db  = in_memory_db();
        let id1 = db.create_vault(&NewVault { vault_name: "V1".into(), is_default: false, ..sample_vault() }).unwrap();
        let id2 = db.create_vault(&NewVault { vault_name: "V2".into(), is_default: false, ..sample_vault() }).unwrap();
        db.set_default_vault(&id1).unwrap();
        assert_eq!(db.get_default_vault().unwrap().vault_id, id1);
        // Switch default
        db.set_default_vault(&id2).unwrap();
        assert_eq!(db.get_default_vault().unwrap().vault_id, id2);
        assert_eq!(db.get_vault(&id1).unwrap().is_default, false);
    }

    #[test]
    fn test_set_default_vault_not_found() {
        let db  = in_memory_db();
        let err = db.set_default_vault("ghost").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_update_vault_promotes_to_default() {
        let db  = in_memory_db();
        let id1 = db.create_vault(&NewVault { vault_name: "V1".into(), is_default: true,  ..sample_vault() }).unwrap();
        let id2 = db.create_vault(&NewVault { vault_name: "V2".into(), is_default: false, ..sample_vault() }).unwrap();
        // Promote V2 via update_vault
        db.update_vault(&id2, "V2", "pk", "epk", true).unwrap();
        assert_eq!(db.get_vault(&id1).unwrap().is_default, false);
        assert_eq!(db.get_vault(&id2).unwrap().is_default, true);
    }
}