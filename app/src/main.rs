use clap::{Parser, builder::Str};

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
                    println!("Adding a new vault");
                    println!("phrase vault new {}", args.value);


                },
                "list" =>{
                    println!("Listing all vaults");
                    println!("phrase vault list");

                },
                "rm" =>{
                    println!("Removing a vault");
                    println!("phrase vault rm {}", args.value);

                },
                "use" =>{
                    println!("Using a vault");
                    println!("phrase vault use {}", args.value);

                },
                "edit" =>{
                    println!("Editing a vault");
                    println!("phrase vault edit {}", args.value)

                },
                _ =>{

                }
            }
        },
        "category" =>{
            match args.actiom.as_str() {
                "new" =>{
                    println!("Adding a new category");
                    println!("phrase category new {}", args.value);

                },
                "list" =>{
                    println!("Listing all categories");
                    println!("phrase category list");



                },
                "rm" =>{
                    println!("Removing a category");
                    println!("phrase category rm {}", args.value);

                },
                "use" =>{
                    println!("Using a category");
                    println!("phrase category use {}", args.value);


                },
                "edit" =>{
                    println!("Editing a category");
                    println!("phrase category edit {}", args.value);

                },
                _ =>{

                }
            }

        },
        "cred" =>{
            let cateory = args.category.unwrap_or_default();
            match args.actiom.as_str() {
                "new" =>{
                    println!("Adding a new entry");
                    println!("phrase cred new {} --category {}", args.value, cateory);
                },
                "list" =>{
                    println!("Listing all entries");
                    println!("phrase cred list --category {}", cateory);

                },
                "rm" =>{
                    println!("Removing an entry");
                    println!("phrase cred rm {} --category {}", args.value, cateory);

                },
                "use" =>{
                    println!("Using an entry");
                    println!("phrase cred use {} --category {}", args.value, cateory);


                },
                "edit" =>{
                    println!("Editing an entry");
                    println!("phrase cred edit {} --category {}", args.value, cateory);


                },
                "get" =>{
                    println!("Getting an entry");
                    println!("phrase cred get {} --category {}", args.value, cateory);

                },
                _ =>{

                }
            }

        },
        _ =>{

        }
    }
}
