use clap::{Parser, builder::Str};
use core::Commands;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // vault | category | cred
    page: String,

    // new | list | rm | use | edit | get
    actiom: String,

    value: String,
    // --category | -c
    #[arg(short, long)]
    category: Option<String>,
}
fn main() {
    let args = Args::parse();
    match args.page.as_str() {
        "vault" =>{
            match args.actiom.as_str() {
                "new" =>{
                    Commands::vault::new(&args.value);
                },
                "list" =>{
                    Commands::vault::list();
                },
                "rm" =>{
                    Commands::vault::rm(&args.value);

                },
                "use" =>{
                    Commands::vault::use_(&args.value);
                },
                _ =>{

                }
            }
        },
        "category" =>{
            match args.actiom.as_str() {
                "new" =>{
                    Commands::category::new(&args.value);

                },
                "list" =>{
                    Commands::category::list();
                },
                "rm" =>{
                    Commands::category::rm(&args.value);

                },
                "use" =>{
                    Commands::category::use_(&args.value);
                },
                _ =>{

                }
            }

        },
        "cred" =>{
            let cateory = args.category.unwrap_or_default();
            match args.actiom.as_str() {
                "new" =>{
                    Commands::entry::new(&args.value, &cateory);
                },
                "list" =>{
                    Commands::entry::list(&cateory);

                },
                "rm" =>{
                    Commands::entry::rm(&args.value, &cateory);
                },
                "edit" =>{
                    Commands::entry::edit(&args.value, &cateory);
                },
                "get" =>{
                    Commands::entry::get(&args.value, &cateory);
                },
                _ =>{

                }
            }

        },
        _ =>{

        }
    }
}
