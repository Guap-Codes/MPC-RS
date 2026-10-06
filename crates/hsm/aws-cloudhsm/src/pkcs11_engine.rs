//! # PKCS#11 Engine Implementation
//!
//! This module contains the core logic for interacting with the AWS CloudHSM via PKCS#11.
//! It handles session management, authentication, and the secure wrapping/unwrapping of 
//! MPC key shares using AES-CBC with a random Initialization Vector (IV).
//!
//! ## Thread Safety & Async Compatibility
//! PKCS#11 C-bindings are inherently synchronous and blocking. To prevent freezing the
//! Tokio async runtime during cryptographic operations, all HSM interactions are
//! offloaded to a dedicated blocking thread pool using `tokio::task::spawn_blocking`.
//! Additionally, the underlying PKCS#11 `Session` is wrapped in an `Arc<Mutex<...>>`
//! to ensure thread-safe, serialized access to the single-threaded HSM session.

use async_trait::async_trait;
use hsm_core::{traits::HsmEngine, error::HsmError};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

use cryptoki::context::{Pkcs11, CInitializeArgs, CInitializeFlags};
use cryptoki::types::AuthPin;
use cryptoki::session::{Session, UserType};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};

/// A thread-safe wrapper around an AWS CloudHSM PKCS#11 session.
///
/// This struct manages the lifecycle of the HSM connection, including initialization,
/// authentication, and the secure wrapping/unwrapping of MPC key shares.
pub struct AwsCloudHsm {
    /// The active PKCS#11 session, protected by a Mutex to ensure thread-safe,
    /// serialized access from concurrent async tasks.
    session: Arc<Mutex<Session>>,
    /// The object handle of the pre-provisioned AES-256 wrap key inside the HSM.
    wrap_key_handle: ObjectHandle,
    /// The local directory path where encrypted (wrapped) key share blobs are stored.
    data_dir: String,
}

impl AwsCloudHsm {
    /// Initializes a new connection to the AWS CloudHSM and prepares it for key wrapping.
    ///
    /// # Arguments
    ///
    /// * `params` - A JSON object containing configuration parameters:
    ///   - `pkcs11_lib` (optional): Path to the CloudHSM PKCS#11 library 
    ///     (default: `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`).
    ///   - `pin` (optional): The Crypto User (CU) PIN for authentication 
    ///     (default: `cuuser:password`).
    ///   - `data_dir` (optional): Local directory for storing wrapped key blobs 
    ///     (default: `./data`).
    ///   - `wrap_key_label` (optional): The label of the AES wrap key pre-provisioned 
    ///     in the HSM (default: `mpc-wrap-key`).
    ///
    /// # Returns
    ///
    /// An initialized `AwsCloudHsm` instance ready to perform cryptographic operations.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if:
    /// - The PKCS#11 library fails to load or initialize.
    /// - No initialized HSM slots are found.
    /// - Authentication with the provided PIN fails.
    /// - The specified wrap key label cannot be found in the HSM.
    pub fn new(params: &Value) -> Result<Self, HsmError> {
        let module_path = params["pkcs11_lib"].as_str().unwrap_or("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so");
        let pin = params["pin"].as_str().unwrap_or("cuuser:password");
        let data_dir = params["data_dir"].as_str().unwrap_or("./data").to_string();
        let wrap_key_label = params["wrap_key_label"].as_str().unwrap_or("mpc-wrap-key");

        // 1. Initialize PKCS#11 context
        let pkcs11 = Pkcs11::new(module_path)
            .map_err(|e| HsmError::Internal(format!("Failed to load PKCS#11 module: {}", e)))?;
        
        // Use CInitializeArgs::new with OS_LOCKING_OK. This tells the PKCS#11 library 
        // that the application (Tokio) will handle OS-level thread synchronization, 
        // which is strictly required for async runtimes.
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| HsmError::Internal(format!("PKCS#11 init failed: {}", e)))?;

        // 2. Open Session and Login
        let slots = pkcs11.get_slots_with_initialized_token()
            .map_err(|e| HsmError::Internal(format!("Failed to get slots: {}", e)))?;
            
        let slot = slots.first()
            .ok_or_else(|| HsmError::Internal("No HSM slots found".into()))?;
        
        let session = pkcs11.open_rw_session(*slot)
            .map_err(|e| HsmError::Internal(format!("Failed to open RW session: {}", e)))?;
        
        // Wrap the PIN in AuthPin for secure memory handling. This ensures the PIN 
        // is allocated in secure memory and automatically zeroized when dropped, 
        // preventing credential scraping from core dumps.
        let auth_pin = AuthPin::new(pin.to_string().into());
        session.login(UserType::User, Some(&auth_pin))
            .map_err(|e| HsmError::Internal(format!("HSM Login failed: {}", e)))?;

        // 3. Find the pre-provisioned AES Wrap Key
        let template = vec![
            Attribute::Label(wrap_key_label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
        ];
        
        let handles = session.find_objects(&template)
            .map_err(|e| HsmError::Internal(format!("Failed to search for wrap key: {}", e)))?;
        
        let wrap_key_handle = handles.first().copied()
            .ok_or_else(|| HsmError::Internal(format!("Wrap key '{}' not found in HSM", wrap_key_label)))?;

        std::fs::create_dir_all(&data_dir).ok();

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            wrap_key_handle,
            data_dir,
        })
    }
}

#[async_trait]
impl HsmEngine for AwsCloudHsm {
    /// Encrypts (wraps) a raw MPC key share using the HSM's internal AES key and saves it to disk.
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
    /// This method generates a random 16-byte Initialization Vector (IV) for each encryption
    /// operation. The IV is prepended to the ciphertext before being written to disk, ensuring
    /// that identical key shares produce different ciphertexts and satisfying FIPS 140-2
    /// requirements for semantic security.
    async fn store(&self, label: &str, data: &[u8]) -> Result<(), HsmError> {
        let session = self.session.clone();
        let key_handle = self.wrap_key_handle;
        let data_to_encrypt = data.to_vec();

        // CRITICAL: PKCS#11 C-bindings are blocking. We MUST use spawn_blocking 
        // to avoid freezing the Tokio async runtime.
        let encrypted_blob = tokio::task::spawn_blocking(move || {
            let session = session.blocking_lock();
            
            // Use AES-CBC with a random IV. While AWS CloudHSM supports AES-GCM, 
            // AES-CBC is universally supported by PKCS#11 HSMs and perfectly matches 
            // our Azure Dedicated HSM implementation, keeping the codebase consistent.
            let iv: [u8; 16] = rand::random();
            let mechanism = Mechanism::AesCbc(iv);

            let ciphertext = session.encrypt(&mechanism, key_handle, &data_to_encrypt)
                .map_err(|e| HsmError::Internal(format!("PKCS#11 Encrypt failed: {}", e)))?;

            // Prepend the IV to the ciphertext so we can use it for decryption later
            let mut final_blob = Vec::with_capacity(16 + ciphertext.len());
            final_blob.extend_from_slice(&iv);
            final_blob.extend_from_slice(&ciphertext);
            
            Ok::<Vec<u8>, HsmError>(final_blob)
        })
        .await
        .map_err(|e| HsmError::Internal(format!("Task join error: {}", e)))??;

        let path = format!("{}/{}.enc", self.data_dir, label);
        
        tokio::fs::write(&path, encrypted_blob).await
            .map_err(|e| HsmError::Internal(format!("Failed to write encrypted share to {}: {}", path, e)))?;

        Ok(())
    }

    /// Retrieves and decrypts (unwraps) an MPC key share from the local filesystem using the HSM.
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
    /// Returns [`HsmError::Internal`] if the file cannot be read, the blob is too short to
    /// contain a valid IV, the HSM decryption fails, or the async task panics.
    async fn get(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        let path = format!("{}/{}.enc", self.data_dir, label);
        let encrypted_blob = tokio::fs::read(&path).await
            .map_err(|e| HsmError::Internal(format!("Failed to read {}: {}", path, e)))?;

        if encrypted_blob.len() < 16 {
            return Err(HsmError::Internal("Encrypted blob is too short to contain an IV".into()));
        }

        // Extract the IV (first 16 bytes) and the ciphertext (the rest)
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&encrypted_blob[..16]);
        let ciphertext = &encrypted_blob[16..];

        let session = self.session.clone();
        let key_handle = self.wrap_key_handle;
        let ciphertext_owned = ciphertext.to_vec();

        let raw_data = tokio::task::spawn_blocking(move || {
            let session = session.blocking_lock();
            let mechanism = Mechanism::AesCbc(iv);

            session.decrypt(&mechanism, key_handle, &ciphertext_owned)
                .map_err(|e| HsmError::Internal(format!("PKCS#11 Decrypt failed: {}", e)))
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

    /// Verifies that the HSM session is still active and responsive.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the session is healthy.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the session has been invalidated (e.g., due to
    /// a network drop between the EC2 instance and the CloudHSM cluster) or the async task panics.
    async fn health_check(&self) -> Result<(), HsmError> {
        let session = self.session.clone();
        tokio::task::spawn_blocking(move || {
            let session = session.blocking_lock();
            session.get_session_info()
                .map_err(|e| HsmError::Internal(format!("Health check failed: {}", e)))
        })
        .await
        .map_err(|e| HsmError::Internal(format!("Task join error: {}", e)))??;
        Ok(())
    }
}

