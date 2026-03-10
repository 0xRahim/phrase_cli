pub mod database {
    use rusqlite::{Connection, Result, params};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use std::fmt;

    // ── Error Type ────────────────────────────────────────────────────────────

    #[derive(Debug)]
    pub enum DbError {
        Rusqlite(rusqlite::Error),
        NotFound(String),
        InvalidInput(String),
    }

    impl fmt::Display for DbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                DbError::Rusqlite(e)      => write!(f, "Database error: {e}"),
                DbError::NotFound(msg)    => write!(f, "Not found: {msg}"),
                DbError::InvalidInput(m)  => write!(f, "Invalid input: {m}"),
            }
        }
    }

    impl From<rusqlite::Error> for DbError {
        fn from(e: rusqlite::Error) -> Self {
            DbError::Rusqlite(e)
        }
    }

    pub type DbResult<T> = std::result::Result<T, DbError>;

    // ── Domain Models ─────────────────────────────────────────────────────────

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub enum EntryType {
        Login,
        Note,
        File,
        Seed,
    }

    impl fmt::Display for EntryType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                EntryType::Login => write!(f, "LOGIN"),
                EntryType::Note  => write!(f, "NOTE"),
                EntryType::File  => write!(f, "FILE"),
                EntryType::Seed  => write!(f, "SEED"),
            }
        }
    }

    impl EntryType {
        pub fn from_str(s: &str) -> DbResult<Self> {
            match s.to_uppercase().as_str() {
                "LOGIN" => Ok(EntryType::Login),
                "NOTE"  => Ok(EntryType::Note),
                "FILE"  => Ok(EntryType::File),
                "SEED"  => Ok(EntryType::Seed),
                other   => Err(DbError::InvalidInput(format!("Unknown entry type: {other}"))),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Vault {
        pub vault_id:        String,
        pub vault_name:      String,
        pub public_key:      String,
        pub enc_private_key: String,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Entry {
        pub id:          String,
        pub vault_id:    String,
        pub alias:       String,
        pub category:    String,
        pub entry_type:  EntryType,
        pub secret_data: String,   // JSON blob
    }

    // ─── New-object DTOs (no ID required from caller) ─────────────────────────

    #[derive(Debug, Clone)]
    pub struct NewVault {
        pub vault_name:      String,
        pub public_key:      String,
        pub enc_private_key: String,
    }

    #[derive(Debug, Clone)]
    pub struct NewEntry {
        pub vault_id:    String,
        pub alias:       String,
        pub category:    String,
        pub entry_type:  EntryType,
        pub secret_data: String,
    }

    // ── Database handle ──────────────────────────────────────────────────────

    pub struct Database {
        conn: Connection,
    }

    impl Database {
        // ── Lifecycle ─────────────────────────────────────────────────────────

        /// Open (or create) a SQLite file at `path`.
        /// Pass `":memory:"` for an in-memory database (great for tests).
        pub fn open(path: &str) -> DbResult<Self> {
            let conn = Connection::open(path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
            let db = Database { conn };
            db.run_migrations()?;
            Ok(db)
        }

        fn run_migrations(&self) -> DbResult<()> {
            self.conn.execute_batch("
                CREATE TABLE IF NOT EXISTS vaults (
                    vault_id        TEXT PRIMARY KEY NOT NULL,
                    vault_name      TEXT NOT NULL UNIQUE,
                    public_key      TEXT NOT NULL,
                    enc_private_key TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entries (
                    id          TEXT PRIMARY KEY NOT NULL,
                    vault_id    TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                    alias       TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    type        TEXT NOT NULL CHECK(type IN ('LOGIN','NOTE','FILE','SEED')),
                    secret_data TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_entries_vault_id ON entries(vault_id);
            ")?;
            Ok(())
        }

        // ══════════════════════════════════════════════════════════════════════
        //  VAULT CRUD
        // ══════════════════════════════════════════════════════════════════════

        /// Create a new vault; returns the generated vault_id.
        pub fn create_vault(&self, new_vault: &NewVault) -> DbResult<String> {
            if new_vault.vault_name.trim().is_empty() {
                return Err(DbError::InvalidInput("vault_name cannot be empty".into()));
            }
            let id = Uuid::new_v4().to_string();
            self.conn.execute(
                "INSERT INTO vaults (vault_id, vault_name, public_key, enc_private_key)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, new_vault.vault_name, new_vault.public_key, new_vault.enc_private_key],
            )?;
            Ok(id)
        }

        /// Fetch a single vault by its ID.
        pub fn get_vault(&self, vault_id: &str) -> DbResult<Vault> {
            self.conn
                .query_row(
                    "SELECT vault_id, vault_name, public_key, enc_private_key
                     FROM vaults WHERE vault_id = ?1",
                    params![vault_id],
                    |row| Ok(Vault {
                        vault_id:        row.get(0)?,
                        vault_name:      row.get(1)?,
                        public_key:      row.get(2)?,
                        enc_private_key: row.get(3)?,
                    }),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows =>
                        DbError::NotFound(format!("Vault '{vault_id}' not found")),
                    other => DbError::Rusqlite(other),
                })
        }

        /// Fetch all vaults.
        pub fn list_vaults(&self) -> DbResult<Vec<Vault>> {
            let mut stmt = self.conn.prepare(
                "SELECT vault_id, vault_name, public_key, enc_private_key FROM vaults ORDER BY vault_name",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(Vault {
                    vault_id:        row.get(0)?,
                    vault_name:      row.get(1)?,
                    public_key:      row.get(2)?,
                    enc_private_key: row.get(3)?,
                })
            })?;
            rows.collect::<Result<Vec<_>>>().map_err(DbError::from)
        }

        /// Update mutable fields of a vault (name, keys).
        pub fn update_vault(
            &self,
            vault_id:        &str,
            vault_name:      &str,
            public_key:      &str,
            enc_private_key: &str,
        ) -> DbResult<()> {
            if vault_name.trim().is_empty() {
                return Err(DbError::InvalidInput("vault_name cannot be empty".into()));
            }
            let affected = self.conn.execute(
                "UPDATE vaults SET vault_name=?1, public_key=?2, enc_private_key=?3
                 WHERE vault_id=?4",
                params![vault_name, public_key, enc_private_key, vault_id],
            )?;
            if affected == 0 {
                return Err(DbError::NotFound(format!("Vault '{vault_id}' not found")));
            }
            Ok(())
        }

        /// Delete a vault (cascades to its entries).
        pub fn delete_vault(&self, vault_id: &str) -> DbResult<()> {
            let affected = self.conn.execute(
                "DELETE FROM vaults WHERE vault_id=?1",
                params![vault_id],
            )?;
            if affected == 0 {
                return Err(DbError::NotFound(format!("Vault '{vault_id}' not found")));
            }
            Ok(())
        }

        // ══════════════════════════════════════════════════════════════════════
        //  ENTRY CRUD
        // ══════════════════════════════════════════════════════════════════════

        /// Create a new entry; returns the generated entry id.
        pub fn create_entry(&self, new_entry: &NewEntry) -> DbResult<String> {
            if new_entry.alias.trim().is_empty() {
                return Err(DbError::InvalidInput("alias cannot be empty".into()));
            }
            // Verify the parent vault exists first for a nicer error.
            self.get_vault(&new_entry.vault_id)?;

            let id = Uuid::new_v4().to_string();
            self.conn.execute(
                "INSERT INTO entries (id, vault_id, alias, category, type, secret_data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    new_entry.vault_id,
                    new_entry.alias,
                    new_entry.category,
                    new_entry.entry_type.to_string(),
                    new_entry.secret_data,
                ],
            )?;
            Ok(id)
        }

        /// Fetch a single entry by its ID.
        pub fn get_entry(&self, entry_id: &str) -> DbResult<Entry> {
            self.conn
                .query_row(
                    "SELECT id, vault_id, alias, category, type, secret_data
                     FROM entries WHERE id=?1",
                    params![entry_id],
                    Self::row_to_entry,
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows =>
                        DbError::NotFound(format!("Entry '{entry_id}' not found")),
                    other => DbError::Rusqlite(other),
                })
        }

        /// Fetch all entries belonging to a vault.
        pub fn list_entries_for_vault(&self, vault_id: &str) -> DbResult<Vec<Entry>> {
            let mut stmt = self.conn.prepare(
                "SELECT id, vault_id, alias, category, type, secret_data
                 FROM entries WHERE vault_id=?1 ORDER BY alias",
            )?;
            let rows = stmt.query_map(params![vault_id], Self::row_to_entry)?;
            rows.collect::<Result<Vec<_>>>().map_err(DbError::from)
        }

        /// Fetch all entries of a specific type inside a vault.
        pub fn list_entries_by_type(
            &self,
            vault_id:   &str,
            entry_type: &EntryType,
        ) -> DbResult<Vec<Entry>> {
            let mut stmt = self.conn.prepare(
                "SELECT id, vault_id, alias, category, type, secret_data
                 FROM entries WHERE vault_id=?1 AND type=?2 ORDER BY alias",
            )?;
            let rows = stmt.query_map(
                params![vault_id, entry_type.to_string()],
                Self::row_to_entry,
            )?;
            rows.collect::<Result<Vec<_>>>().map_err(DbError::from)
        }

        /// Update mutable fields of an entry.
        pub fn update_entry(
            &self,
            entry_id:    &str,
            alias:       &str,
            category:    &str,
            entry_type:  &EntryType,
            secret_data: &str,
        ) -> DbResult<()> {
            if alias.trim().is_empty() {
                return Err(DbError::InvalidInput("alias cannot be empty".into()));
            }
            let affected = self.conn.execute(
                "UPDATE entries SET alias=?1, category=?2, type=?3, secret_data=?4
                 WHERE id=?5",
                params![alias, category, entry_type.to_string(), secret_data, entry_id],
            )?;
            if affected == 0 {
                return Err(DbError::NotFound(format!("Entry '{entry_id}' not found")));
            }
            Ok(())
        }

        /// Delete a single entry.
        pub fn delete_entry(&self, entry_id: &str) -> DbResult<()> {
            let affected = self.conn.execute(
                "DELETE FROM entries WHERE id=?1",
                params![entry_id],
            )?;
            if affected == 0 {
                return Err(DbError::NotFound(format!("Entry '{entry_id}' not found")));
            }
            Ok(())
        }

        // ── Internal helpers ──────────────────────────────────────────────────

        fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
            let type_str: String = row.get(4)?;
            let entry_type = EntryType::from_str(&type_str)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(Entry {
                id:          row.get(0)?,
                vault_id:    row.get(1)?,
                alias:       row.get(2)?,
                category:    row.get(3)?,
                entry_type,
                secret_data: row.get(5)?,
            })
        }
    }
}

// ── Re-exports ────────────────────────────────────────────────────────────────
// Flatten `crate::database::database::*`  →  `crate::database::*`
// so callers (and tests) can simply write `use crate::database::Database`.
pub use database::{
    Database, DbError, DbResult,
    EntryType, Entry, Vault,
    NewVault, NewEntry,
};

// ── Test modules ─────────────────────────────────────────────────────────────
#[cfg(test)]
#[path = "unit_tests.rs"]
mod unit_tests;

#[cfg(test)]
#[path = "integration_tests.rs"]
mod integration_tests;