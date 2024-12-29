//! Secure logging for sensitive application data
//!
//! Provides encrypted logging capabilities with the following features:
//! - AES-256-GCM encryption for all log messages
//! - Asynchronous processing via background thread to minimize performance impact
//! - Automatic key derivation using SHA-256
//! - Compatible with the standard `log` crate interface
//! - Built-in message queuing with backpressure
//!
//! # Security Considerations
//! - Messages are encrypted before being written to disk
//! - Each log entry uses a unique random nonce
//! - The encryption key never touches the disk
//! - Messages are queued in memory only temporarily before encryption

use std::{
  fs::{File, OpenOptions},
  io::{BufRead, BufReader, Write},
  path::{Path, PathBuf},
  thread::{self, JoinHandle},
  sync::{Once, Arc},
};
use aes_gcm::{
  aead::{Aead, KeyInit},
  Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use crossbeam_channel::{bounded, Sender};
use log::{Level, LevelFilter, Metadata, Record};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};

mod error;
pub use error::Error;

/// Size of the message queue for the background logging thread
const QUEUE_SIZE: usize = 10_000;

static INIT: Once = Once::new();

/// Message types that can be sent to the background logging thread
enum LogMessage {
  /// A log entry pending encryption and writing
  Entry(String),

  /// Signals the background thread to finish processing and exit
  Shutdown,
}

/// Core secure logging implementation
pub struct SecureLogger {
  /// Channel sender for queueing log messages
  sender: Sender<LogMessage>,

  /// Background thread handle
  _worker: Arc<JoinHandle<()>>,
}

impl SecureLogger {
  /// Create a new encrypted logger for writing secure logs
  ///
  /// # Arguments
  /// * `key` - Encryption key (can be any string)
  /// * `log_path` - Path where encrypted logs will be written
  ///
  /// # Example
  /// ```no_run
  /// use secure_log::SecureLogger;
  ///
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let logger = SecureLogger::encrypt("my-secret-key", "application.log")?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn encrypt(key: String, log_path: impl Into<PathBuf>) -> Result<Self, Error> {
    // Derive 32-byte key bytes
    let key_bytes = Self::derive_key(&key);

    // Create cipher from the provided key
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
      .map_err(|_| Error::InvalidKey)?;

    // Create channel for message passing
    let (sender, receiver) = bounded(QUEUE_SIZE);

    // Open log file
    let mut file = OpenOptions::new()
      .create(true)
      .write(true)
      .truncate(true)
      .open(log_path.into())?;

    // Spawn background worker thread
    let worker = thread::Builder::new()
      .name("secure-logger".into())
      .spawn(move || {
        while let Ok(message) = receiver.recv() {
          match message {
            LogMessage::Entry(log_entry) => {
              // Generate random nonce for this message
              let mut nonce_bytes = [0u8; 12];
              OsRng.fill_bytes(&mut nonce_bytes);
              let nonce = Nonce::from_slice(&nonce_bytes);

              // Attempt to encrypt the log entry
              if let Ok(encrypted) = cipher.encrypt(
                nonce,
                log_entry.as_bytes()
              ) {
                // Combine nonce and encrypted data
                let mut combined = nonce.to_vec();
                combined.extend_from_slice(&encrypted);

                // Base64 encode and write to file
                let encoded = BASE64.encode(combined);
                let _ = writeln!(file, "{}", encoded);
                let _ = file.flush();
              }
            }

            LogMessage::Shutdown => break,
          }
        }
      })?;

    let logger = Self {
      sender,
      _worker: Arc::new(worker),
    };

    // Initialize the global logger if not already initialized
    INIT.call_once(|| {
      log::set_logger(Box::leak(Box::new(logger.clone())))
        .map(|()| log::set_max_level(LevelFilter::Trace))
        .expect("Failed to initialize logger");
    });

    Ok(logger)
  }

  /// Decrypt a log file and write the contents to a new file
  ///
  /// # Arguments
  /// * `key` - The same key used for encryption
  /// * `input_path` - Path to the encrypted log file
  ///
  /// # Returns
  /// * `String` - The decrypted contents of the log file
  ///
  /// # Example
  /// ```no_run
  /// use secure_log::SecureLogger;
  ///
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// let contents = SecureLogger::decrypt("my-secret-key", "application.log")?;
  /// std::fs::write("decrypted.log", contents)?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn decrypt(
    key: String,
    input_path: impl AsRef<Path>
  ) -> Result<String, Error> {
    // Derive 32-byte key bytes
    let key_bytes = Self::derive_key(&key);

    // Initialize cipher with the key
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
      .map_err(|_| Error::InvalidKey)?;

    // Open input and output files
    let input_file = File::open(input_path)?;
    let reader = BufReader::new(input_file);
    let mut decrypted_contents = String::new();

    // Process each line
    for line in reader.lines() {
      let line = line?;

      // Decode the base64 line
      let encrypted_data = BASE64.decode(line).map_err(|_| Error::InvalidData)?;

      // First 12 bytes are the nonce, rest is the encrypted message
      if encrypted_data.len() < 12 {
        return Err(Error::InvalidData);
      }

      let (nonce_bytes, encrypted_message) = encrypted_data.split_at(12);
      let nonce = Nonce::from_slice(nonce_bytes);

      // Decrypt the message
      let decrypted = cipher
        .decrypt(nonce, encrypted_message)
        .map_err(|_| Error::DecryptionFailed)?;

      // Convert to string and append
      decrypted_contents.push_str(&String::from_utf8_lossy(&decrypted));
      decrypted_contents.push('\n');
    }

    Ok(decrypted_contents)
  }

  /// Derives a 32-byte encryption key using SHA-256
  fn derive_key(key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().to_vec()
  }
}

// Implement Clone to allow sharing the logger between threads
impl Clone for SecureLogger {
  fn clone(&self) -> Self {
    Self {
      sender: self.sender.clone(),
      _worker: self._worker.clone(),
    }
  }
}

impl log::Log for SecureLogger {
  fn enabled(&self, metadata: &Metadata) -> bool {
    metadata.level() <= Level::Trace
  }

  fn log(&self, record: &Record) {
    if self.enabled(record.metadata()) {
      // Format log message with timestamp
      let log_entry = format!(
        "{} [{:5}] {}",
        Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        record.level(),
        record.args()
      );

      // Send to worker thread via channel
      let _ = self.sender.send(LogMessage::Entry(log_entry));
    }
  }

  fn flush(&self) {
    // No-op as worker thread handles flushing
  }
}

impl Drop for SecureLogger {
  fn drop(&mut self) {
    // Send shutdown signal to worker thread
    let _ = self.sender.send(LogMessage::Shutdown);
  }
}
