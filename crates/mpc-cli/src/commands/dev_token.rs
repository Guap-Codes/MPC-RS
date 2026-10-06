//! # Development JWT Generation Command
//!
//! This module provides a local-only utility for generating administrative JSON 
//! Web Tokens (JWTs) for testing and development purposes.
//!
//! ## Operational Context
//! In a production environment, JWTs are issued by a dedicated Identity Provider (IdP) 
//! (e.g., Keycloak, Auth0). However, for local development and CI testing, this 
//! command allows operators to mint valid, cryptographically signed tokens directly 
//! from the CLI using the repository's local `config/private.pem` key.
//!
//! ⚠️ **Security Warning**: This command must **never** be used in production. 
//! The `private.pem` file should be excluded from version control and restricted 
//! to authorized developers only. Production environments must rely on a proper IdP.

use anyhow::{Result, Context};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize, Deserialize};
use std::fs;

/// Represents the payload of the generated development JWT.
///
/// This struct mirrors the `Claims` structure expected by the `mpc-auth` crate,
/// ensuring that tokens generated locally are immediately compatible with the 
/// API Gateway and Coordinator authentication middleware.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// The subject (entity) the token represents (e.g., "admin-cli").
    sub: String,
    /// The intended audience of the token (e.g., "mpc-api" or "mpc-coordinator").
    aud: String,        
    /// The issuer of the token (hardcoded to "mpc-rs" for local dev).
    iss: String,        
    /// The Role-Based Access Control (RBAC) roles granted to the subject.
    roles: Vec<String>,
    /// Expiration time as a UTC Unix timestamp.
    exp: usize,
    /// Issued-at time as a UTC Unix timestamp.
    iat: usize,
}

/// Command-line arguments for the `dev-token` subcommand.
#[derive(clap::Args, Debug, Clone)]
pub struct DevTokenArgs {
    /// The target audience for the token.
    ///
    /// Use `mpc-coordinator` for administrative CLI operations, or `mpc-api` 
    /// for testing public API gateway endpoints.
    #[arg(long, default_value = "mpc-coordinator")]
    pub audience: String,
}

/// Executes the local JWT generation command.
///
/// This function reads the local RSA private key, constructs a `Claims` payload 
/// with a 24-hour expiration, signs it using RS256, and prints the resulting 
/// token to standard output.
///
/// # Arguments
///
/// * `args` - The parsed CLI arguments containing the target audience.
///
/// # Returns
///
/// `Ok(())` if the token was successfully generated and printed.
///
/// # Errors
///
/// Returns an error if:
/// - The `config/private.pem` file cannot be found or read.
/// - The PEM file is malformed or not a valid RSA private key.
/// - The JWT encoding process fails.
///
/// # Note
///
/// This command runs entirely locally and does **not** require a network 
/// connection to the MPC Coordinator.
pub fn execute(args: DevTokenArgs) -> Result<()> {
    // Read the local development private key
    let private_key = fs::read("config/private.pem")
        .context("Failed to read config/private.pem. Are you running from the project root?")?;
    let encoding_key = EncodingKey::from_rsa_pem(&private_key)?;
    
    // Calculate current Unix timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    // Construct the claims payload
    let claims = Claims {
        sub: "admin-cli".to_string(),
        aud: args.audience, // Dynamically set via CLI flag
        iss: "mpc-rs".to_string(),       
        roles: vec!["admin".to_string()], // Grant full admin privileges for local dev
        iat: now,
        exp: now + 86400, // Valid for 24 hours
    };
    
    // Sign and encode the token
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)?;
    
    // Print only the raw token to stdout so it can be easily copied or piped:
    // export MPC_TOKEN=$(./target/release/mpc-cli dev-token)
    println!("{}", token);
    Ok(())
}

