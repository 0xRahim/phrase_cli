use clap::{Parser, Subcommand};
use commands::Commands;
use core::commands;
use core::ui;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    page: Page,
}

#[derive(Subcommand, Debug)]
enum Page {
    /// Vault operations
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },

    /// Category operations
    Category {
        #[command(subcommand)]
        action: CategoryAction,
    },

    /// Credential operations
    Cred {
        #[command(subcommand)]
        action: CredAction,

        /// Category name
        #[arg(short, long)]
        category: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum VaultAction {
    New { name: Option<String> },
    List,
    Rm { name: Option<String> },
    Use { name: Option<String> },
}

#[derive(Subcommand, Debug)]
enum CategoryAction {
    New { name: Option<String> },
    List,
    Rm { name: Option<String> },
    Use { name: Option<String> },
}

#[derive(Subcommand, Debug)]
enum CredAction {
    New { name: Option<String> },
    List,
    Rm { name: Option<String> },
    Edit { name: Option<String> },
    Get { name: Option<String> },
}

fn main() {
    ui::print_banner();

    let cli = Cli::parse();

    match cli.page {
        // ---------------- VAULT ----------------
        Page::Vault { action } => match action {
            VaultAction::New { name } => {
                let name = require_value(
                    name,
                    "Vault name is required.\n\nUsage: phrase vault new <vault_name>\nExample: phrase vault new personal",
                );
                Commands::vault::new(&name);
            }
            VaultAction::List => Commands::vault::list(),
            VaultAction::Rm { name } => {
                let name = require_value(
                    name,
                    "Vault name is required.\n\nUsage: phrase vault rm <vault_name>\nExample: phrase vault rm personal",
                );
                Commands::vault::rm(&name);
            }
            VaultAction::Use { name } => {
                let name = require_value(
                    name,
                    "Vault name is required.\n\nUsage: phrase vault use <vault_name>\nExample: phrase vault use personal",
                );
                Commands::vault::use_(&name);
            }
        },

        // ---------------- CATEGORY ----------------
        Page::Category { action } => match action {
            CategoryAction::New { name } => {
                let name = require_value(
                    name,
                    "Category name is required.\n\nUsage: phrase category new <name>\nExample: phrase category new work",
                );
                Commands::category::new(&name);
            }
            CategoryAction::List => Commands::category::list(),
            CategoryAction::Rm { name } => {
                let name = require_value(
                    name,
                    "Category name is required.\n\nUsage: phrase category rm <name>\nExample: phrase category rm work",
                );
                Commands::category::rm(&name);
            }
            CategoryAction::Use { name } => {
                let name = require_value(
                    name,
                    "Category name is required.\n\nUsage: phrase category use <name>\nExample: phrase category use work",
                );
                Commands::category::use_(&name);
            }
        },

        // ---------------- CRED ----------------
        Page::Cred { action, category } => {
            let category = category.unwrap_or_else(|| {
                ui::info("No category specified. Using 'default'.");
                "default".to_string()
            });

            match action {
                CredAction::New { name } => {
                    let name = require_value(
                        name,
                        "Entry name is required.\n\nUsage: phrase cred new <entry_name> [--category <name>]\nExample: phrase cred new github --category work",
                    );
                    Commands::entry::new(&name, &category);
                }
                CredAction::List => {
                    Commands::entry::list(&category);
                }
                CredAction::Rm { name } => {
                    let name = require_value(
                        name,
                        "Entry name is required.\n\nUsage: phrase cred rm <entry_name> [--category <name>]\nExample: phrase cred rm github --category work",
                    );
                    Commands::entry::rm(&name, &category);
                }
                CredAction::Edit { name } => {
                    let name = require_value(
                        name,
                        "Entry name is required.\n\nUsage: phrase cred edit <entry_name> [--category <name>]\nExample: phrase cred edit github --category work",
                    );
                    Commands::entry::edit(&name, &category);
                }
                CredAction::Get { name } => {
                    let name = require_value(
                        name,
                        "Entry name is required.\n\nUsage: phrase cred get <entry_name> [--category <name>]\nExample: phrase cred get github --category work",
                    );
                    Commands::entry::get(&name, &category);
                }
            }
        }
    }
}

// ---------------- HELPERS ----------------

fn require_value(value: Option<String>, msg: &str) -> String {
    match value {
        Some(v) if !v.is_empty() => v,
        _ => exit_with_error(msg),
    }
}

fn exit_with_error(msg: &str) -> ! {
    ui::failure(msg);
    println!();
    std::process::exit(1);
}
