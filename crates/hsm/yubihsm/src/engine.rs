//! # YubiHSM Engine Implementation
//!
//! This module contains the core logic for interacting with the YubiHSM via its
//! native Rust SDK. It handles session management, authentication, and the secure
//! wrapping/unwrapping of MPC key shares.

use async_trait::async_trait;
use hsm_core::{traits::HsmEngine, error::HsmError};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use yubihsm::{Client, Connector, Credentials, connector::HttpConfig};

/// A thread-safe wrapper around a YubiHSM client session.
///
/// This struct manages the lifecycle of the HSM connection, including initialization,
/// authentication, and the secure wrapping/unwrapping of MPC key shares.
pub struct YubiHsm {
    /// The active YubiHSM client, protected by a Mutex to ensure thread-safe,
    /// serialized access from concurrent async tasks.
    client: Arc<Mutex<Client>>,
    /// The object ID of the pre-provisioned AES wrap key inside the YubiHSM.
    wrap_key_id: u16,
    /// The local directory path where encrypted (wrapped) key share blobs are stored.
    data_dir: String,
}

impl YubiHsm {
    /// Initializes a new connection to the YubiHSM and prepares it for key wrapping.
    ///
    /// # Arguments
    ///
    /// * `params` - A JSON object containing configuration parameters:
    ///   - `connector_url` (optional): The URL of the YubiHSM connector 
    ///     (default: `http://127.0.0.1:12345`). *Note: Currently uses `HttpConfig::default()`.*
    ///   - `auth_key_id` (optional): The authentication key ID (default: `1`).
    ///   - `password` (optional): The authentication password (default: `"password"`).
    ///   - `wrap_key_id` (optional): The object ID of the AES wrap key (default: `2`).
    ///   - `data_dir` (optional): Local directory for storing wrapped key blobs (default: `./data`).
    ///
    /// # Returns
    ///
    /// An initialized `YubiHsm` instance ready to perform cryptographic operations.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the YubiHSM connector fails to initialize,
    /// authentication fails, or the device is unreachable.
    pub fn new(params: &Value) -> Result<Self, HsmError> {
        let _connector_url = params["connector_url"].as_str().unwrap_or("http://127.0.0.1:12345");
        let auth_key_id = params["auth_key_id"].as_u64().unwrap_or(1) as u16;
        let password = params["password"].as_str().unwrap_or("password");
        let wrap_key_id = params["wrap_key_id"].as_u64().unwrap_or(2) as u16;
        let data_dir = params["data_dir"].as_str().unwrap_or("./data").to_string();

        // HttpConfig does not implement FromStr, so we use the default 
        // (which points to http://127.0.0.1:12345, matching our fallback).
        // Note: To support custom URLs in the future, add the `url` crate to Cargo.toml,
        // parse the string into a `url::Url`, and use `HttpConfig::new(url)`.
        let http_config = HttpConfig::default();
            
        let connector = Connector::http(&http_config);
        let credentials = Credentials::from_password(auth_key_id, password.as_bytes());
        
        let client = Client::open(connector, credentials, true)
            .map_err(|e| HsmError::Internal(format!("Failed to connect to YubiHSM: {}", e)))?;

        std::fs::create_dir_all(&data_dir).ok();

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            wrap_key_id,
            data_dir,
        })
    }
}

#[async_trait]
impl HsmEngine for YubiHsm {
    /// Encrypts (wraps) a raw MPC key share using the YubiHSM's internal AES key and saves it to disk.
    ///
    /// # Arguments
    ///
    /// * `label` - A unique identifier for the key share, used as the filename.
    /// * `data` - The raw, unencrypted MPC key share bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the share was successfully encrypted and written to disk.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the HSM encryption fails, the async task panics,
    /// or the local filesystem write operation fails.
    ///
    /// # Note
    ///
    /// The YubiHSM natively handles the generation of the Initialization Vector (IV) and 
    /// the AES-CCM authentication tag during the `wrap_data` operation, ensuring FIPS 140-2 
    /// Level 2/3 compliant semantic security.
    async fn store(&self, label: &str, data: &[u8]) -> Result<(), HsmError> {
        let client = self.client.clone();
        let wrap_key_id = self.wrap_key_id;
        let data_to_wrap = data.to_vec();

        // CRITICAL: YubiHSM SDK calls are synchronous and blocking. We MUST use 
        // spawn_blocking to avoid freezing the Tokio async runtime.
        let wrapped_data = tokio::task::spawn_blocking(move || {
            let client = client.blocking_lock();
            client.wrap_data(wrap_key_id, data_to_wrap)
                .map_err(|e| HsmError::Internal(format!("YubiHSM wrap failed: {}", e)))
        })
        .await
        .map_err(|e| HsmError::Internal(format!("Task join error: {}", e)))??;

        let path = format!("{}/{}.enc", self.data_dir, label);
        
        // Use `into_vec()` to consume the Message and extract the raw byte vector
        // for efficient filesystem writing without unnecessary cloning.
        let bytes_to_write = wrapped_data.into_vec();
        
        tokio::fs::write(&path, bytes_to_write).await
            .map_err(|e| HsmError::Internal(format!("Failed to write to {}: {}", path, e)))?;

        Ok(())
    }

    /// Retrieves and decrypts (unwraps) an MPC key share from the local filesystem using the YubiHSM.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier of the key share to retrieve.
    ///
    /// # Returns
    ///
    /// The raw, decrypted MPC key share bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the file cannot be read, the blob is corrupted,
    /// the HSM decryption fails, or the async task panics.
    async fn get(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        let path = format!("{}/{}.enc", self.data_dir, label);
        let wrapped_bytes = tokio::fs::read(&path).await
            .map_err(|e| HsmError::Internal(format!("Failed to read {}: {}", path, e)))?;

        let client = self.client.clone();
        let wrap_key_id = self.wrap_key_id;

        let raw_data = tokio::task::spawn_blocking(move || {
            let client = client.blocking_lock();
            
            // Use `from_vec()` which takes ownership of the Vec<u8>.
            // We use map_err instead of expect to safely handle disk corruption without panicking.
            let message = yubihsm::wrap::Message::from_vec(wrapped_bytes)
                .map_err(|e| HsmError::Internal(format!("Corrupted YubiHSM wrap message on disk: {}", e)))?;
                
            client.unwrap_data(wrap_key_id, message)
                .map_err(|e| HsmError::Internal(format!("YubiHSM unwrap failed: {}", e)))
        })
        .await
        .map_err(|e| HsmError::Internal(format!("Task join error: {}", e)))??;

        Ok(raw_data)
    }

    /// A no-op for this implementation.
    ///
    /// # Note
    ///
    /// In the MPC-RS architecture, key shares are generated locally in secure RAM by the
    /// MPC nodes during the DKG ceremony, and then passed to the HSM *only* for wrapping.
    /// The HSM is not used to generate the ECDSA/EdDSA key material itself.
    async fn generate_key(&self, _label: &str) -> Result<(), HsmError> {
        Ok(())
    }

    /// Deletes the locally stored encrypted key share blob.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier of the key share to delete.
    ///
    /// # Returns
    ///
    /// `Ok(())` regardless of whether the file existed, ensuring idempotent cleanup.
    async fn delete_key(&self, label: &str) -> Result<(), HsmError> {
        let path = format!("{}/{}.enc", self.data_dir, label);
        tokio::fs::remove_file(path).await.ok();
        Ok(())
    }

    /// Verifies that the YubiHSM is connected and responsive.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the device responds with valid information.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the device is unreachable, the session is invalid,
    /// or the async task panics.
    async fn health_check(&self) -> Result<(), HsmError> {
        let client = self.client.clone();
        tokio::task::spawn_blocking(move || {
            let client = client.blocking_lock();
            client.device_info()
                .map_err(|e| HsmError::Internal(format!("YubiHSM health check failed: {}", e)))
        })
        .await
        .map_err(|e| HsmError::Internal(format!("Task join error: {}", e)))??;
        
        Ok(())
    }
}




