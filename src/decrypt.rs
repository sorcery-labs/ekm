use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, Oaep};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use anyhow::{Result, Context};
use std::fs::File;
use std::io::Read;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn read_pass_encrypted_data(file_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut file = File::open(file_path).context("Failed to open encrypted key file")?;
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).context("Failed to read encrypted key")?;

    let salt = file_contents[..16].to_vec();
    let encrypted_data = file_contents[16..].to_vec();

    Ok((salt, encrypted_data))
}

pub fn read_rsa_encrypted_data(file_path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(file_path).context("Failed to open encrypted key file")?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).context("Failed to read encrypted key")?;
    Ok(encrypted_data)
}

pub fn decrypt_private_key_with_pass(encrypted_key: &[u8], password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut key_derived = [0u8; 32]; // AES-256 key size
    let _ = pbkdf2::<Hmac<Sha256>>(password, salt, 100_000, &mut key_derived);
    let cipher = Aes256Cbc::new_from_slices(&key_derived, &salt[..16]).context("Failed to create cipher")?;
    cipher.decrypt_vec(encrypted_key).map_err(Into::into)
}

/// Decrypts data using RSA private key and OAEP padding.
pub fn decrypt_private_key_with_rsa(encrypted_data: &[u8], privkey_pem: &str) -> Result<Vec<u8>> {
    let privkey = RsaPrivateKey::from_pkcs8_pem(privkey_pem).context("Failed to parse private key")?;
    let padding = Oaep::new::<Sha256>();

    let decrypted_data = privkey.decrypt(padding, encrypted_data)
        .context("Failed to decrypt with RSA private key")?;
    Ok(decrypted_data)
}