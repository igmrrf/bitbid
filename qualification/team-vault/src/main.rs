fn main() {
    match bitbid_team_vault_qualification::suite::run(true) {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("qualification failed: {e}");
            std::process::exit(1)
        }
    }
}
