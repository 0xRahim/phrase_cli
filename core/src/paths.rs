/// Centralized storage paths for phrase.
///
/// Layout:
///   release  →  $HOME/.local/share/phrase/
///   debug    →  $HOME/.local/share/phrase-dev/
///
/// Sub-structure:
///   <app_dir>/
///   ├── phrase.db          (SQLite vault database)
///   └── uploads/           (ECIES-wrapped encrypted files)
///
/// Both `db_path()` and `uploads_dir()` create missing directories on first
/// call, so callers never need to mkdir manually.
use std::path::PathBuf;

// ── App root ──────────────────────────────────────────────────────────────────

/// Returns the root storage directory for this build profile.
///
/// Uses `dirs::data_dir()` which resolves to:
///   Linux/BSDs  →  $XDG_DATA_HOME  (fallback: $HOME/.local/share)
///   macOS       →  $HOME/Library/Application Support
fn app_dir() -> PathBuf {
    let base = dirs::data_dir().expect(
        "Cannot determine user data directory. \
         Make sure $HOME (Linux) or equivalent is set.",
    );

    if cfg!(debug_assertions) {
        base.join("phrase-dev") // debug / cargo run
    } else {
        base.join("phrase") // cargo build --release
    }
}

// ── Public surface ────────────────────────────────────────────────────────────

/// Absolute path to the SQLite database file.
///
/// Creates `<app_dir>/` if it does not yet exist.
pub fn db_path() -> PathBuf {
    let dir = app_dir();
    ensure_dir(&dir, "app storage directory");
    dir.join("phrase.db")
}

/// Absolute path to the uploads directory where encrypted files are stored.
///
/// Creates `<app_dir>/uploads/` if it does not yet exist.
pub fn uploads_dir() -> PathBuf {
    let dir = app_dir().join("uploads");
    ensure_dir(&dir, "uploads directory");
    dir
}

/// Returns the encrypted path for a plaintext file path.
///
/// The encrypted file is placed in `uploads/` with its original filename
/// plus the `.phrased` extension, keeping user files out of arbitrary
/// directories.
///
/// Example:
///   `/home/user/docs/secret.pdf`  →  `<uploads_dir>/secret.pdf.phrased`
pub fn encrypted_file_path(plaintext_path: &str) -> PathBuf {
    let file_name = std::path::Path::new(plaintext_path)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("unnamed"))
        .to_string_lossy();

    uploads_dir().join(format!("{file_name}.phrased"))
}

/// Returns the decrypted output path for an encrypted file stored in uploads.
///
/// Strips the `.phrased` suffix and writes back to the uploads directory
/// so the decrypted file lands alongside the encrypted one, not wherever
/// the original plaintext happened to live.
///
/// Example:
///   `<uploads_dir>/secret.pdf.phrased`  →  `<uploads_dir>/secret.pdf`
pub fn decrypted_file_path(encrypted_path: &str) -> PathBuf {
    let stripped = encrypted_path.strip_suffix(".phrased").unwrap_or(encrypted_path);
    let file_name = std::path::Path::new(stripped)
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("unnamed"))
        .to_string_lossy()
        .into_owned();

    uploads_dir().join(file_name)
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn ensure_dir(path: &PathBuf, label: &str) {
    if let Err(e) = std::fs::create_dir_all(path) {
        eprintln!("phrase: failed to create {label} at {}: {e}", path.display());
        std::process::exit(1);
    }
}