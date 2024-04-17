use ethers::prelude::*;
use anyhow::{Result, Context};
use rpassword::prompt_password;

pub mod encrypt;
pub mod decrypt;

use decrypt::{read_pass_encrypted_data, read_rsa_encrypted_data};
use decrypt::{decrypt_private_key_with_pass, decrypt_private_key_with_rsa};

pub fn load_wallet_from_pass_encrypted_file(file_path: &str) -> Result<LocalWallet> {
    let password = prompt_password("Enter password to decrypt private key: ")?;
    let password_bytes = password.as_bytes();

    let (salt, encrypted_data) = read_pass_encrypted_data(file_path)?;

    let decrypted_key_bytes = decrypt_private_key_with_pass(&encrypted_data, password_bytes, &salt)?;
    let wallet = LocalWallet::from_bytes(&decrypted_key_bytes)
    .context("Failed to create wallet from private key")?;

    println!("Wallet loaded with address: {}", wallet.address());

    Ok(wallet)
}

pub fn load_wallet_from_rsa_encrypted_file(file_path: &str, privkey_pem: &str) -> Result<LocalWallet> {
    let encrypted_data = read_rsa_encrypted_data(file_path)?;

    let decrypted_key_bytes = decrypt_private_key_with_rsa(&encrypted_data, privkey_pem)
        .context("Failed to decrypt Ethereum private key using RSA")?;
    
    let wallet = LocalWallet::from_bytes(&decrypted_key_bytes)
        .context("Failed to create wallet from decrypted private key")?;

    println!("Wallet loaded with address: {}", wallet.address());

    Ok(wallet)
}