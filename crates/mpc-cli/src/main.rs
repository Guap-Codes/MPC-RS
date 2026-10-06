//! # MPC-RS Administrative CLI Entry Point
//!
//! This is the main entry point for the `mpc-cli` tool. It orchestrates the
//! initialization sequence: parsing command-line arguments, loading configuration,
//! establishing a secure mTLS connection to the coordinator, and dispatching
//! the requested administrative command.
//!
//! ## Execution Flow
//! 1. Initialize tracing/logging.
//! 2. Parse CLI arguments using `clap`.
//! 3. Handle local-only commands (like `dev-token`) immediately, bypassing network setup.
//! 4. Load the `admin.toml` configuration file.
//! 5. Establish an mTLS + JWT authenticated gRPC connection to the Coordinator.
//! 6. Dispatch to the specific command handler module.

#![allow(clippy::double_must_use)]

mod cli;
mod client;
mod config;
mod commands;

use clap::Parser;
use anyhow::Result;
use tracing_subscriber::fmt;

/// The main asynchronous entry point for the `mpc-cli` application.
///
/// # Execution Flow
///
/// - **Local Commands**: If the user requests `dev-token`, it is executed locally
///   using the private key, and the program exits immediately without attempting
///   to connect to the coordinator.
/// - **Network Commands**: For all other commands, the CLI loads the mTLS configuration,
///   establishes a secure gRPC channel, and dispatches the command to the appropriate
///   handler in the `commands` module.
///
/// # Returns
///
/// Returns `Ok(())` if the command executes successfully, or an `anyhow::Error`
/// if configuration loading, network connection, or command execution fails.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging to stderr for immediate visibility
    fmt::init();
    
    // Parse CLI arguments
    let args = cli::Cli::parse();

    // Handle DevToken locally without needing a network connection.
    // Extract the arguments from the DevToken variant and execute immediately.
    if let cli::Commands::DevToken(token_args) = args.command {
        commands::dev_token::execute(token_args)?;
        return Ok(());
    }

    // Load admin configuration (mTLS certs, coordinator URL)
    let cfg = config::AdminConfig::load(&args.config)?;
    
    // Establish secure gRPC connection to the coordinator
    let mut admin_client = client::AdminClient::connect(
        &cfg.coordinator.url,
        &cfg.tls.ca_cert,
        &cfg.tls.client_cert,
        &cfg.tls.client_key,
    ).await?;
    
    // Dispatch to the appropriate command handler
    match args.command {
        cli::Commands::AuxGen => {
            commands::aux_gen::execute(&mut admin_client).await?;
        }
        cli::Commands::Keygen { curve, threshold } => {
            commands::keygen::execute(&mut admin_client, &curve, threshold).await?;
        }
        cli::Commands::Rotate { key_id } => {
            commands::rotate::execute(&mut admin_client, &key_id).await?;
        }
        cli::Commands::Status => {
            commands::status::execute(&mut admin_client).await?;
        }
        cli::Commands::Backup { output_dir } => {
            commands::backup::execute(&mut admin_client, &output_dir).await?;
        }
        cli::Commands::Drain { chain, from_address, target_address, derivation_path } => {
            commands::drain::execute(&mut admin_client, &chain, &target_address, &from_address, &derivation_path).await?;
        }
        cli::Commands::SolanaKeygen => {
            commands::solana_keygen::execute(&mut admin_client).await?;
        }
        // Satisfy the compiler's exhaustive pattern check.
        // This is safe because we already handled it and returned early above.
        cli::Commands::DevToken(_) => unreachable!(),
    }
    
    Ok(())
}

