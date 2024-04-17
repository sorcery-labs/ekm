# Ethereum Key Management Library

This Rust library provides functionality for generating Ethereum wallets and encrypting private keys using either a password or an RSA public key. It's designed for secure management and storage of Ethereum private keys.

## Features

- Generate Ethereum wallets
- Encrypt private keys with a password
- Encrypt private keys using RSA public key encryption
- Command-line interface for easy interaction

## Installation

To use this library, you must have Rust installed on your machine. [Install Rust and Cargo](https://www.rust-lang.org/tools/install) if they are not already installed.

1. Clone this repository:
   ```bash
   git clone https://github.com/sorcery-labs/ekm
   cd ethereum_key_manager
   ```
2. Build the project:
    ```bash
    cargo build --release
    ```
3. The executable will be available under `target/release/`.

## Usage

The two cli apps allow you to generate wallets with encrypted private keys. Below are the commands and options available.

### Generating and Encrypting a Private Key

1. **Generate and encrypt a private key with a password:**
    ```bash
    cargo run --bin key_gen pass --output pk.dat
    ```
You will be prompted to enter a password that will be used to encrypt the ethereum private key.

2. **Generate and encrypt a private key with an RSA public key:**
    ```bash
    cargo run --bin key_gen rsa --pubkey path/to/public_key.pem --output pk.dat
    ```
Ensure that your public key is in PEM format.

### Loading and Decrypting a Private Key

1. **Decrypt a private key encrypted with a password:**
    ```bash
    cargo run --bin key_load pass --file pk.dat
    ````
You will be prompted to enter the password used for encryption.

2. **Decrypt a private key encrypted with an RSA private key:**
    ```bash
    cargo run --bin key_load rsa --rsakey path/to/private_key.pem --file pk.dat
    ```
Ensure that the private key is in PEM format.

## Generating RSA Keys

You can generate RSA keys using OpenSSL with the following commands:

- **Generate RSA Private Key:**

    ```bash
    openssl genpkey -algorithm RSA -out rsa_private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```
- **Extract RSA Public Key:**
    ```bash
    openssl rsa -pubout -in rsa_private_key.pem -out rsa_public_key.pem
    ```

## TODO

- [ ] Reduce the time the unencrypted keys live in memory
- [ ] Generate keys in secure enclave

## License

This project is licensed under [MIT License](LICENSE).



