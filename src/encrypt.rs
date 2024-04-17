use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{Rng, thread_rng};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Oaep};
use sha2::Sha256;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Write;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Encrypts data using a password and writes the result to a file.
pub fn encrypt_private_key_with_pass(key: &[u8], password: &[u8], file_path: &str) -> Result<()> {
    let salt: Vec<u8> = generate_salt();
    let key_derived = derive_key(password, &salt)?;
    let encrypted_data = aes_encrypt(key, &key_derived, &salt)?;
    write_to_file(file_path, &salt, &encrypted_data)
}

/// Encrypts data using the public key at the specified path and writes the result to a file.
pub fn encrypt_private_key_with_pubkey(key: &[u8], pubkey_file_path: &str, file_path: &str) -> Result<()> {
    let pubkey_pem = std::fs::read_to_string(pubkey_file_path)
        .context("Failed to read public key file")?;
    let encrypted_data = rsa_encrypt(key, &pubkey_pem)?;
    write_to_file(file_path, &encrypted_data, &[])
}

/// Generates a random salt for encryption.
fn generate_salt() -> Vec<u8> {
    thread_rng().sample_iter(rand::distributions::Standard).take(16).collect()
}

/// Derives a key using PBKDF2.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = [0u8; 32];
    let _mac = Hmac::<Sha256>::new_from_slice(password)
        .expect("HMAC can take key of any size");

    let _ = pbkdf2::<Hmac<Sha256>>(password, &salt, 100_000, &mut key);
    Ok(key.to_vec())
}

/// Encrypts data using AES encryption.
fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).expect("Invalid key or IV length!");
    Ok(cipher.encrypt_vec(data))
}

/// Encrypts data using RSA encryption.
fn rsa_encrypt(data: &[u8], pubkey_pem: &str) -> Result<Vec<u8>> {
    let pubkey = RsaPublicKey::from_public_key_pem(pubkey_pem).context("Failed to parse public key")?;
    let padding = Oaep::new::<Sha256>();
    let mut rng = thread_rng();
    pubkey.encrypt(&mut rng, padding, data).context("Failed to encrypt with RSA public key")
}

/// Writes data to a file, optionally prepending it with a salt.
fn write_to_file(file_path: &str, salt: &[u8], data: &[u8]) -> Result<()> {
    let mut file = File::create(file_path).context("Unable to create file")?;
    if !salt.is_empty() {
        file.write_all(salt).context("Failed to write salt")?;
    }
    file.write_all(data).context("Failed to write encrypted data")
}