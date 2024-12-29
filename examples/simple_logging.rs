use secure_log::SecureLogger;
use log::{error, warn, info, debug, trace};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let key = "super-secret-key-for-testing";
  let log_path = "example.log";

  // Initialize the encrypted logger
  let _logger = SecureLogger::encrypt(key.to_string(), log_path)?;

  // Log some messages
  error!("This is an error message log");
  warn!("This is a warning message log");
  info!("This is an info message log");
  debug!("This is a debug message log");
  trace!("This is a trace message log");

  // Give the background thread time to process logs
  std::thread::sleep(std::time::Duration::from_millis(100));

  // Read and display encrypted contents
  println!("**** Encrypted Log Contents ***");
  let encrypted = std::fs::read_to_string(log_path)?;
  println!("{}", encrypted);

  // Decrypt and display contents
  println!("*** Decrypted Log Contents ***");
  let decrypted = SecureLogger::decrypt(key.to_string(), log_path)?;
  println!("{}", decrypted);

  Ok(())
}
