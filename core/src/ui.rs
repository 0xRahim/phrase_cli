// ─── Terminal Styling Primitives ─────────────────────────────────────────────
//
// Zero-dependency ANSI helpers for phrase's output.
// Import with: use crate::ui;  (or wherever this module lives)
// ─────────────────────────────────────────────────────────────────────────────


// ─── Imports
use std::io::{self, Write};
// ─────────────────────────────────────────────────────────────────────────────


// ── Raw ANSI codes ────────────────────────────────────────────────────────────
pub const RESET:   &str = "\x1b[0m";
pub const BOLD:    &str = "\x1b[1m";
pub const DIM:     &str = "\x1b[2m";

pub const CYAN:    &str = "\x1b[36m";
pub const BCYAN:   &str = "\x1b[96m";   // bright cyan  — primary accent
pub const GREEN:   &str = "\x1b[32m";
pub const BGREEN:  &str = "\x1b[92m";   // success
pub const RED:     &str = "\x1b[31m";
pub const BRED:    &str = "\x1b[91m";   // error
pub const YELLOW:  &str = "\x1b[33m";
pub const BYELLOW: &str = "\x1b[93m";   // warning / prompt
pub const WHITE:   &str = "\x1b[97m";
pub const GRAY:    &str = "\x1b[90m";   // muted / decorative

// ── Glyphs ────────────────────────────────────────────────────────────────────
pub const OK:     &str = "✓";
pub const FAIL:   &str = "✗";
pub const BULLET: &str = "◆";
pub const ARROW:  &str = "›";
pub const DOT:    &str = "·";
pub const BAR:    &str = "─";

// ── Banner ────────────────────────────────────────────────────────────────────
pub fn print_banner() {
    let logo: &[&str] = &[
        " ██████╗ ██╗  ██╗██████╗  █████╗ ███████╗███████╗",
        " ██╔══██╗██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝",
        " ██████╔╝███████║██████╔╝███████║███████╗█████╗  ",
        " ██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝  ",
        " ██║     ██║  ██║██║  ██║██║  ██║███████║███████╗",
        " ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝",
    ];

    println!();
    for line in logo {
        println!("{BCYAN}{BOLD}{line}{RESET}");
    }
    println!();
    println!(
        "{GRAY}  secure credential vault  {DOT}  v1.0.0  {DOT}  local-first  {DOT}  non-custodial{RESET}"
    );
    println!("{GRAY}  {}{RESET}", BAR.repeat(54));
    println!();
}

// ── Layout helpers ────────────────────────────────────────────────────────────
pub fn separator() {
    println!("{GRAY}  {}{RESET}", BAR.repeat(48));
}

/// Prints a titled section header with a rule beneath it.
pub fn section(title: &str) {
    println!();
    println!("{BOLD}{WHITE}  {title}{RESET}");
    println!("{GRAY}  {}{RESET}", BAR.repeat(title.len() + 2));
}

// ── Status lines ──────────────────────────────────────────────────────────────
pub fn success(msg: &str) {
    println!("{BGREEN}{BOLD}  {OK}  {RESET}{WHITE}{msg}{RESET}");
}

pub fn failure(msg: &str) {
    println!("{BRED}{BOLD}  {FAIL}  {RESET}{WHITE}{msg}{RESET}");
}

pub fn info(msg: &str) {
    println!("{GRAY}  {ARROW}  {RESET}{msg}");
}

pub fn warn(msg: &str) {
    println!("{BYELLOW}{BOLD}  !  {RESET}{YELLOW}{msg}{RESET}");
}

// ── Data display ──────────────────────────────────────────────────────────────

/// Bullet-list item, e.g. for vault/entry listings.
pub fn list_item(name: &str) {
    println!("{CYAN}  {BULLET}  {RESET}{BOLD}{WHITE}{name}{RESET}");
}

/// Bullet-list item with a right-aligned badge (e.g. "default").
pub fn list_item_tagged(name: &str, tag: &str) {
    println!(
        "{CYAN}  {BULLET}  {RESET}{BOLD}{WHITE}{name:<28}{RESET}{GRAY}{tag}{RESET}"
    );
}

/// Key-value pair, aligned for readability.
pub fn kv(key: &str, value: &str) {
    println!("{GRAY}  {key:<14}{RESET}{BCYAN}{value}{RESET}");
}

/// Muted key-value pair (for IDs, paths, metadata).
pub fn kv_dim(key: &str, value: &str) {
    println!("{GRAY}  {key:<14}{DIM}{value}{RESET}");
}

/// Masked field — shows key but hides value (e.g. password copied to clipboard).
pub fn kv_masked(key: &str, notice: &str) {
    println!(
        "{GRAY}  {key:<14}{RESET}{GRAY}{DIM}{notice}{RESET}"
    );
}

/// Prompt prefix — used before interactive password/enter prompts.
pub fn prompt_prefix(label: &str) {
    print!("{BYELLOW}{BOLD}  {ARROW}  {RESET}{BOLD}{label}{RESET} ");
}

// Clear terminal screen - used to clean the terminal texts 
pub fn clear_terminal() {
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
}