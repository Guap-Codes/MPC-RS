//! # AES-256-GCM Encrypted File Storage
//!
//! This module provides a software-based, encrypted file storage mechanism intended
//! for development, testing, and local environments. It acts as a "Soft HSM" by
//! encrypting data at rest using AES-256-GCM.
//!
//! ## Storage Format
//! Each encrypted blob is stored as a separate file with the `.enc` extension.
//! The file format is strictly: `[12-byte nonce] || [ciphertext + 16-byte GCM authentication tag]`.
//!
//! ## Key Management
//! The master encryption key is either loaded from a hex-encoded string provided
//! at initialization, or read from a `master.key` file in the storage directory.
//! If neither exists, a new cryptographically secure random key is generated and
//! persisted to `master.key`.
//!
//! ⚠️ **Security Warning**: This implementation is intended for **development and testing only**.
//! It does not provide the hardware-backed security guarantees of a true HSM (e.g., YubiHSM, AWS CloudHSM).
//! In production, always use a hardware-backed [`HsmEngine`](hsm_core::traits::HsmEngine) implementation.

use std::path::{Path, PathBuf};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;
use hsm_core::error::HsmError;

/// Manages encrypted file persistence using AES-256-GCM.
///
/// This struct holds the initialized cipher and the base directory for all
/// encrypted key share blobs.
pub struct FileStore {
    storage_dir: PathBuf,
    cipher: Aes256Gcm,
}

impl FileStore {
    /// Opens or creates an encrypted file store in the specified directory.
    ///
    /// # Arguments
    ///
    /// * `storage_dir` – The directory path where encrypted blobs and the `master.key` will reside.
    /// * `existing_hex_key` – An optional master key as a hex-encoded string. If `None`, the store 
    ///   will attempt to load an existing `master.key` from the directory, or generate a new 
    ///   random 32-byte key and persist it if none exists.
    ///
    /// # Returns
    ///
    /// An initialized `FileStore` ready to encrypt and decrypt data.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Serialization`] if the provided hex key is invalid or not exactly 32 bytes,
    /// or if an existing `master.key` file is malformed.
    /// Returns [`HsmError::Io`] if directory creation or file I/O operations fail.
    pub fn new(storage_dir: &str, existing_hex_key: Option<&str>) -> Result<Self, HsmError> {
        let dir = PathBuf::from(storage_dir);
        std::fs::create_dir_all(&dir)?;

        let master_key = if let Some(hex_key) = existing_hex_key {
            let bytes = hex::decode(hex_key)
                .map_err(|e| HsmError::Serialization(format!("master key hex: {e}")))?;
            if bytes.len() != 32 {
                return Err(HsmError::Serialization("master key must be 32 bytes".into()));
            }
            bytes
        } else {
            let key_path = dir.join("master.key");
            if key_path.exists() {
                let hex_str = std::fs::read_to_string(&key_path)?;
                let bytes = hex::decode(hex_str.trim())
                    .map_err(|e| HsmError::Serialization(format!("master key file hex: {e}")))?;
                if bytes.len() != 32 {
                    return Err(HsmError::Serialization(format!(
                        "master key file must decode to 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                bytes
            } else {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                std::fs::write(&key_path, hex::encode(&key))?;
                key.to_vec()
            }
        };      

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(key);

        Ok(Self {
            storage_dir: dir,
            cipher,
        })
    }

    /// Returns the full filesystem path where the encrypted blob for a given `label` is stored.
    fn blob_path(&self, label: &str) -> PathBuf {
        self.storage_dir.join(format!("{label}.enc"))
    }

    /// Encrypts `plaintext` using AES-256-GCM and writes it to disk under the given `label`.
    ///
    /// # Arguments
    ///
    /// * `label` – A unique identifier for the data, used as the filename (without the `.enc` extension).
    /// * `plaintext` – The raw, unencrypted data to be securely stored.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the AES-GCM encryption operation fails.
    /// Returns [`HsmError::Io`] if writing the file to disk fails.
    pub async fn store(&self, label: &str, plaintext: &[u8]) -> Result<(), HsmError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HsmError::Internal(format!("encryption failed: {e}")))?;

        let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        let path = self.blob_path(label);
        tokio::fs::write(&path, &blob).await?;
        Ok(())
    }

    /// Retrieves and decrypts the blob stored under the given `label`.
    ///
    /// # Arguments
    ///
    /// * `label` – The unique identifier of the data to retrieve.
    ///
    /// # Returns
    ///
    /// The decrypted, raw plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::KeyNotFound`] if the file does not exist.
    /// Returns [`HsmError::Serialization`] if the file is too small to contain a valid nonce and tag.
    /// Returns [`HsmError::Internal`] if decryption fails (indicating a wrong key, corrupted data, or tampering).
    /// Returns [`HsmError::Io`] if reading the file from disk fails.
    pub async fn get(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        let path = self.blob_path(label);
        if !path.exists() {
            return Err(HsmError::KeyNotFound(label.to_string()));
        }

        let blob = tokio::fs::read(&path).await?;
        if blob.len() < 12 + 16 {
            return Err(HsmError::Serialization("invalid file format".into()));
        }

        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plain = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| HsmError::Internal("decryption failed (wrong key or corrupt data)".into()))?;

        Ok(plain)
    }

    /// Securely deletes the encrypted blob for the given `label`.
    ///
    /// # Note
    ///
    /// To hinder forensic recovery, this method first overwrites the file with zeros 
    /// before unlinking it from the filesystem. Note that this is a best-effort secure 
    /// delete and may not be effective on all filesystems (e.g., SSDs with wear leveling).
    ///
    /// # Arguments
    ///
    /// * `label` – The unique identifier of the data to delete.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Io`] if metadata retrieval, overwriting, or file removal fails.
    pub async fn delete(&self, label: &str) -> Result<(), HsmError> {
        let path = self.blob_path(label);
        if path.exists() {
            // Overwrite with zeros before unlinking to hinder recovery.
            let meta = tokio::fs::metadata(&path).await?;
            let len = meta.len() as usize;
            let zeros = Zeroizing::new(vec![0u8; len]);
            tokio::fs::write(&path, zeros.as_slice()).await?;
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }

    /// Performs a liveness check to ensure the storage directory is accessible.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Io`] if the storage directory does not exist or lacks read permissions.
    pub async fn health_check(&self) -> Result<(), HsmError> {
        let _ = tokio::fs::metadata(&self.storage_dir).await?;
        Ok(())
    }
}


