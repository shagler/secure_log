//! Error types for secure logging operations

use std::io;
use thiserror::Error;

/// Errors that can occur during secure logging operations
#[derive(Error, Debug)]
pub enum Error {
  /// An I/O error occurred when working with log files
  #[error("I/O error: {0}")]
  Io(#[from] io::Error),

  /// The encryption key was invalid
  #[error("Invalid encryption key")]
  InvalidKey,

  /// The encrypted log file contains invalid data
  #[error("Invalid log file data")]
  InvalidData,

  /// Failed to decrypt a log message
  #[error("Failed to decrypt log message")]
  DecryptionFailed,

  /// Required environment variable is missing
  #[error("Missing required environment variable")]
  MissingKey,
}
