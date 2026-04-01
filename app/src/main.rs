use clap::Parser;
use commands::Commands;
use core::commands;
use core::ui;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// vault | category | cred
    page: String,

    /// new | list | rm | use | edit | get
    action: String,

    /// Target name (vault name, entry alias, etc.)
    value: Option<String>,

    /// Category name
    #[arg(short, long)]
    category: Option<String>,
}

fn main() {
    ui::print_banner();

    let args = Args::parse();
    let value = args.value.as_deref().unwrap_or("");

    match args.page.as_str() {
        "vault" => {
            let requires_value = matches!(args.action.as_str(), "new" | "rm" | "use");
            if requires_value && value.is_empty() {
                let msg = match args.action.as_str() {
                    "new" => {
                        "Vault name is required.\n\nUsage: phrase vault new <vault_name>\nExample: vault new personal"
                    }
                    "rm" => {
                        "Vault name is required.\n\nUsage: phrase vault rm <vault_name>\nExample: vault rm personal"
                    }
                    "use" => {
                        "Vault name is required.\n\nUsage: phrase vault use <vault_name>\nExample: vault use personal"
                    }
                    _ => "Vault name is required for this action.",
                };

                exit_with_error(&msg);
            }

            match args.action.as_str() {
                "new" => Commands::vault::new(value),
                "list" => Commands::vault::list(),
                "rm" => Commands::vault::rm(value),
                "use" => Commands::vault::use_(value),
                other => unknown_action("vault", other),
            }
        }

        "category" => match args.action.as_str() {
            "new" => Commands::category::new(value),
            "list" => Commands::category::list(),
            "rm" => Commands::category::rm(value),
            "use" => Commands::category::use_(value),
            other => unknown_action("category", other),
        },

        "cred" => {
            let category = args.category.as_deref().unwrap_or("default");

            // Check if action requires a value
            let requires_value = matches!(args.action.as_str(), "new" | "rm" | "edit" | "get");

            if requires_value && value.is_empty() {
                let msg = match args.action.as_str() {
                    "new" => {
                        "Entry name is required.\n\nUsage: phrase cred new <entry_name> [--category <name>]\nExample: cred new github --category work"
                    }
                    "rm" => {
                        "Entry name is required.\n\nUsage: phrase cred rm <entry_name> [--category <name>]\nExample: cred rm github --category work"
                    }
                    "edit" => {
                        "Entry name is required.\n\nUsage: phrase cred edit <entry_name> [--category <name>]\nExample: cred edit github --category work"
                    }
                    "get" => {
                        "Entry name is required.\n\nUsage: phrase cred get <entry_name> [--category <name>]\nExample: cred get github --category work"
                    }
                    _ => "Entry name is required for this action.",
                };

                exit_with_error(&msg);
            }

            // Optional: inform user if default category is used
            if args.category.is_none() {
                ui::info("No category specified. Using 'default'.");
            }

            match args.action.as_str() {
                "new" => Commands::entry::new(value, category),
                "list" => Commands::entry::list(category),
                "rm" => Commands::entry::rm(value, category),
                "edit" => Commands::entry::edit(value, category),
                "get" => Commands::entry::get(value, category),
                other => unknown_action("cred", other),
            }
        }

        other => {
            let msg = &format!(
                "Unknown page '{other}'. Try: vault | category | cred"
            );
            exit_with_error(&msg);
        }
    }
}

fn unknown_action(page: &str, action: &str) {
    let msg = format!("Unknown action '{action}' for '{page}'");
    exit_with_error(&msg);
}

fn exit_with_error(msg: &str) -> ! {
    ui::failure(msg);
    println!();
    std::process::exit(1);
}
