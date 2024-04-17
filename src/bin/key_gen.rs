use clap::{App, Arg, SubCommand};
use ethers::prelude::*;
use rpassword::prompt_password;
use regex::Regex;
use anyhow::{Result};
use ekm::encrypt::{encrypt_private_key_with_pass, encrypt_private_key_with_pubkey};

struct Config {
    output_path: String,
    key_type: KeyType,
}

enum KeyType {
    Password(String),
    PublicKey(String),
}

fn main() -> Result<()> {
    let config = parse_arguments()?;
    let wallet = generate_ethereum_wallet()?;
    encrypt_private_key(&wallet, &config)?;

    Ok(())
}

fn parse_arguments() -> Result<Config> {
    let matches = App::new("Ethereum Key Generator")
        .version("0.1.0")
        .author("rad")
        .about("Generates and encrypts et hirum pk")
        .subcommand(SubCommand::with_name("pass")
            .about("Encrypts with a password")
            .arg(Arg::with_name("OUTPUT")
                .help("Sets the output file for the encrypted key")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("rsa")
            .about("Encrypts with a RSA public key")
            .arg(Arg::with_name("PUBKEY")
                .help("Path to the RSA public key file")
                .required(true))
            .arg(Arg::with_name("OUTPUT")
                .help("Sets the output file for the encrypted key")
                .required(true)
                .index(2)))
        .get_matches();

    match matches.subcommand() {
        Some(("pass", sub_m)) => {
            let output_path = sub_m.value_of("OUTPUT").unwrap().to_string();
            let password = prompt_for_valid_password()?;
            Ok(Config {
                output_path,
                key_type: KeyType::Password(password),
            })
        },
        Some(("rsa", sub_m)) => {
            let pubkey_path = sub_m.value_of("PUBKEY").unwrap().to_string();
            let output_path = sub_m.value_of("OUTPUT").unwrap().to_string();
            Ok(Config {
                output_path,
                key_type: KeyType::PublicKey(pubkey_path),
            })
        },
        _ => Err(anyhow::anyhow!("Invalid command; please specify 'pass' or 'rsa'.")),
    }
}

fn generate_ethereum_wallet() -> Result<LocalWallet> {
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    println!("Generated Ethereum Address: {}", wallet.address());
    Ok(wallet)
}

fn encrypt_private_key(wallet: &LocalWallet, config: &Config) -> Result<()> {
    match &config.key_type {
        KeyType::Password(password) => {
            encrypt_private_key_with_pass(wallet.signer().to_bytes().as_slice(), password.as_bytes(), &config.output_path)?;
            println!("Private key encrypted with password and saved successfully.");
        },
        KeyType::PublicKey(pubkey_path) => {
            encrypt_private_key_with_pubkey(wallet.signer().to_bytes().as_slice(), &pubkey_path, &config.output_path)?;
            println!("Private key encrypted with RSA public key and saved successfully.");
        }
    }
    Ok(())
}

fn prompt_for_valid_password() -> Result<String> {
    let password_regex = Regex::new(r"^.{12,}.*[\W_]")?;
    loop {
        let password = prompt_password("Enter a password to encrypt the private key (min 12 characters, at least one special character): ")?;
        if password_regex.is_match(&password) {
            return Ok(password);
        } else {
            println!("Password does not meet the strength requirements.");
        }
    }
}
