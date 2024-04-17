use clap::{App, Arg, SubCommand};
use anyhow::{Context, Result};
use ekm::{load_wallet_from_pass_encrypted_file, load_wallet_from_rsa_encrypted_file};

fn main() -> Result<()> {
    let matches = App::new("Ethereum Wallet Loader")
        .version("0.1.0")
        .author("rad")
        .about("Loads Ethereum wallets from pass or rsa encrypted files")
        .subcommand(SubCommand::with_name("pass")
            .about("Loads a wallet encrypted with a password")
            .arg(Arg::with_name("FILE")
                .help("Path to the encrypted private key file")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("rsa")
            .about("Loads a wallet encrypted with an RSA public key")
            .arg(Arg::with_name("RSA_KEY")
                .help("Path to the RSA private key file")
                .required(true))
            .arg(Arg::with_name("FILE")
                .help("Path to the encrypted private key file")
                .required(true)
                .index(2)))
        .get_matches();

    match matches.subcommand() {
        Some(("pass", sub_m)) => {
            let file_path = sub_m.value_of("FILE").unwrap();
            let _ = load_wallet_from_pass_encrypted_file(file_path)?;
        },
        Some(("rsa", sub_m)) => {
            let file_path = sub_m.value_of("FILE").unwrap();
            let rsa_key_path = sub_m.value_of("RSA_KEY").unwrap();
            let priv_key_pem = std::fs::read_to_string(&rsa_key_path).context("Failed to read private key file")?;
            let _ = load_wallet_from_rsa_encrypted_file(file_path, &priv_key_pem)?;
        },
        _ => return Err(anyhow::anyhow!("Invalid command; please specify 'password' or 'rsa'."))
    }

    Ok(())
}