//! # Encrypted Share Backup Command
//!
//! This module implements the CLI command for retrieving and saving encrypted 
//! MPC key share backups from all registered nodes in the cluster.
//!
//! ## Disaster Recovery Context
//! In the MPC-RS architecture, raw key shares are never stored in plaintext. 
//! Instead, they are wrapped (encrypted) by the node's local Hardware Security 
//! Module (HSM). This command retrieves those HSM-encrypted blobs. 
//! 
//! ⚠️ **Security Warning**: These backup files are the *only* way to recover a 
//! vault if a node's local storage is destroyed. They must be stored in 
//! geographically distributed, physically secure, offline locations (e.g., 
//! bank safe deposit boxes). While encrypted by the HSM, losing the HSM device 
//! *and* the backup simultaneously results in permanent loss of the vault.

use crate::client::AdminClient;
use crate::client::coordinator_proto::RequestBackupRequest;
use anyhow::{Result, Context};
use std::fs;
use tracing::info;

/// Executes the backup retrieval command.
///
/// This function requests the latest encrypted key share from every node in the 
/// cluster and writes them to the specified local directory.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient`.
/// * `output_dir` - The local filesystem path where the `.enc` backup files will be saved.
///
/// # Returns
///
/// `Ok(OK)` if all backups were successfully retrieved and written to disk.
///
/// # Errors
///
/// Returns an error if:
/// - The output directory cannot be created.
/// - The gRPC request to the Coordinator fails.
/// - Writing any individual backup file to disk fails (e.g., due to permissions).
///
/// # Security Note
///
/// The resulting files are named `node_<id>_backup.enc`. They are encrypted using 
/// the specific node's HSM master wrap key. They can only be decrypted by restoring 
/// them to an HSM that possesses the corresponding master key.
pub async fn execute(client: &mut AdminClient, output_dir: &std::path::Path) -> Result<()> {
    info!("Requesting encrypted share backups from all nodes...");
    
    // Ensure the target directory exists
    fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    
    let request = tonic::Request::new(RequestBackupRequest {});
    let response = client.inner.request_backup(request).await?;
    let backups = response.into_inner().backups;
    
    // Iterate over a reference (&backups) so the vector is not moved/consumed
    for backup in &backups {
        let file_path = output_dir.join(format!("node_{}_backup.enc", backup.node_id));
        fs::write(&file_path, &backup.encrypted_share)
            .with_context(|| format!("Failed to write backup for node {}", backup.node_id))?;
        info!("Saved backup for node {} to {:?}", backup.node_id, file_path);
    }
    
    // Now `backups` is still valid and we can safely call `.len()`
    println!("Successfully backed up {} nodes to {:?}", backups.len(), output_dir);
    println!("⚠️  WARNING: Store these files securely offline. They are encrypted with the node's HSM master key.");
    println!("            Losing both the HSM hardware and these files will result in permanent vault loss.");
    
    Ok(())
}


