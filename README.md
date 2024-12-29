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

See this example of `examples/simple_logger.rs`:

```rust
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
```

Here is the printed output of that example:
```
**** Encrypted Log Contents ***
bOycZFr8CohsL4k2Xo6CiShLP+fwGl2p9MB19jxvPfZ07HgcI/DDDzyizSSTbitLBlaY8fsy+qUC//Dz7n+B7tH6NUIB6I3W2OGtCiVmlz25Z9uBz3Ghgw==
irFz/wBbLo9ZCv86QTB7ZF3QkCVcU9yTXBBNG85j1yatu+K1eJa5Rsymukgd2aRPamGbM3QeAp0ZCBHL8gFZLBj39HHXLNsY54k9kYXq3HK/wur4204uzWI=
EifcvYx0NEnjEa/LLb0kKRdlyL0C79M8kp6QBigg/3yXYptGXErvpAF80BWiEY7mU9CiC8moR06nB+ie6B2AvwkYF1ccqdz6pzFFw/Eigvos8DzWkawX
5daaiqCojHBW7gBxeAmoMztbheQeH+QmaXQ+m0TkUStaQ2ogi/e+MziQrO9aAmxjwKg2bhdtYoL7xZi6aF3jyUOWHYsUquGHOBB//rcvVLXNs44SiYpz
R5Yvit3WDMW0lyuDL4SzbaaWEToLU5GZ+p00obt5yp7etZ83JrD93Sd1GvcAMrP1+MdAgAjREihOl4xy5NlSKvTcn2aXISwkOAs1i6p8drmkJ5rdMHkv

*** Decrypted Log Contents ***
2024-12-29 21:23:44.414 [ERROR] This is an error message log
2024-12-29 21:23:44.414 [WARN ] This is a warning message log
2024-12-29 21:23:44.414 [INFO ] This is an info message log
2024-12-29 21:23:44.414 [DEBUG] This is a debug message log
2024-12-29 21:23:44.414 [TRACE] This is a trace message log
```
