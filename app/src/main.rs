use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // vault | category | cred
    page: String,

    // new | list | rm | use | edit | get
    actiom: String,

    // --category | -c
    #[arg(short, long)]
    category: String,
}
fn main() {
    let args = Args::parse();
    println!("{:?}", args);
}
