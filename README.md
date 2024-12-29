# secure_log

A secure logging implementation for Rust that encrypts log messages using
AES-256-GCM and processes them asynchronously to minimize performance impact.

## Features

* Asynchronous log processing in a background thread
* AES-256-GCM encryption with unique nonce per message
* Non-blocking operating with message queuing
* Integration with the standard `log` crate
* Simple API for both logging and decryption

## Installation

Add to your `Cargo.toml`:
```tmol
[dependencies]
secure_log = "0.1.0"
log = "0.4"
```

## Usage

### Writing Encrypted Logs
```rust
use secure_log::SecureLogger;
use log::info;

fn main() -> Result<()> {
  // Load encryption key from environment
  let key = std::env::var("ENCRYPT_LOG_KEY").expect("Encryption key required");

  // Initialize the logger
  let logger = SecureLogger::encrypt(key, "application.log")?;

  let secret_value = "secure log test!!!";

  // Use standard log macros - all output is encrypted
  info!("Application started");
  info!("Sensitive data: {}", secret_value);

  Ok(())
}
```

### Decrypting Logs
```rust
use secure_log::SecureLogger;

fn main() -> Result<()> {
  // Use the same key that was used for encryption
  let key = std::env::var("ENCRYPT_LOG_KEY").expect("Encryption key required");

  // Decrypt the log file
  let contents = SecureLogger::decrypt(key, "application.log")?;

  // TODO: save contents to file (decrypted.log) with std::fs

  Ok(()
}
```

## Setting the Encryption Key

The encryption key can be any string. I recommend setting it in your environment:
```bash
export ENCRYPT_LOG_KEY="your-secret-key-here"
```
or
```bash
export ENCRYPT_LOG_KEY=$(openssl rand -hex 32)
```
