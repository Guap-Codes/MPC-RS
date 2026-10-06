//! # Key Management and Address Derivation
//!
//! This module provides the `MpcKeyManager`, which handles BIP32/BIP44 hierarchical 
//! deterministic (HD) key derivation, address generation, and persistent state tracking 
//! using a SQLite database.
//!
//! ## Architecture
//! In the MPC-RS architecture, the `MpcKeyManager` is responsible for deriving 
//! public keys and addresses from a master `Xpub`. It maintains a monotonic counter 
//! in the database to ensure that receiving (`m/0/*`) and change (`m/1/*`) addresses 
//! are generated sequentially without gaps, which is critical for wallet recovery 
//! and UTXO management.

use bitcoin::{Address, Network, key::CompressedPublicKey};
use bitcoin::bip32::{DerivationPath, Xpub};
use sqlx::{SqlitePool, Row};

/// Manages HD wallet derivation and address state persistence.
pub struct MpcKeyManager {
    pool: SqlitePool,
    master_xpub: Xpub,
    network: Network,
}

impl MpcKeyManager {
    /// Initializes a new `MpcKeyManager` and runs database migrations.
    ///
    /// # Arguments
    ///
    /// * `pool` - The SQLite connection pool.
    /// * `master_xpub` - The master extended public key for the vault.
    /// * `network` - The target Bitcoin network (e.g., Mainnet, Testnet).
    ///
    /// # Errors
    ///
    /// Returns an error if database migrations fail or the pool is invalid.
    pub async fn new(pool: SqlitePool, master_xpub: Xpub, network: Network) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Run migrations on startup to ensure schema is up to date
        sqlx::migrate!("./migrations").run(&pool).await?;
        
        Ok(Self { pool, master_xpub, network })
    }

    /// Derives a child address and its compressed public key from a given BIP32 path.
    ///
    /// # Arguments
    ///
    /// * `path_str` - The derivation path string (e.g., `"m/0/0"`).
    ///
    /// # Returns
    ///
    /// A tuple containing the derived `Address` (P2WPKH) and the `CompressedPublicKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    pub fn derive_address(&self, path_str: &str) -> Result<(Address, CompressedPublicKey), Box<dyn std::error::Error + Send + Sync>> {
        let path: DerivationPath = path_str.parse()?;
        
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let child_xpub = self.master_xpub.derive_pub(&secp, &path)?;
        
        let compressed_pubkey = child_xpub.to_pub();
        let address = Address::p2wpkh(&compressed_pubkey, self.network);
        
        Ok((address, compressed_pubkey))
    }

    /// Generates the next internal (change) address and increments the database counter.
    ///
    /// # Note
    ///
    /// Change addresses use the BIP44 internal chain path `m/1/<index>`. This method 
    /// is transactional to prevent race conditions in concurrent environments.
    ///
    /// # Returns
    ///
    /// The newly derived change `Address`.
    ///
    /// # Errors
    ///
    /// Returns an error if database operations or key derivation fail.
    pub async fn get_next_change_address(&self) -> Result<Address, Box<dyn std::error::Error + Send + Sync>> {
        let mut tx = self.pool.begin().await?;
        
        let row = sqlx::query("SELECT internal_index FROM key_manager_state WHERE id = 1")
            .fetch_one(&mut *tx).await?;
        let index: i64 = row.try_get(0)?;
        
        sqlx::query("UPDATE key_manager_state SET internal_index = ? WHERE id = 1")
            .bind(index + 1).execute(&mut *tx).await?;
        tx.commit().await?;

        // Use non-hardened path for change addresses (BIP44 standard)
        let path = format!("m/1/{}", index); 
        let (address, pubkey) = self.derive_address(&path)?;
        
        self.record_address(&address.to_string(), &path, &pubkey.to_bytes(), true).await?;
        
        Ok(address)
    }

    /// Generates the next external (receiving) address and increments the database counter.
    ///
    /// # Note
    ///
    /// Receiving addresses use the BIP44 external chain path `m/0/<index>`. This method 
    /// is transactional to prevent race conditions in concurrent environments.
    ///
    /// # Returns
    ///
    /// The newly derived receiving `Address`.
    ///
    /// # Errors
    ///
    /// Returns an error if database operations or key derivation fail.
    pub async fn get_next_receiving_address(&self) -> Result<Address, Box<dyn std::error::Error + Send + Sync>> {
        let mut tx = self.pool.begin().await?;
        
        let row = sqlx::query("SELECT external_index FROM key_manager_state WHERE id = 1")
            .fetch_one(&mut *tx).await?;
        let index: i64 = row.try_get(0)?;
        
        sqlx::query("UPDATE key_manager_state SET external_index = ? WHERE id = 1")
            .bind(index + 1).execute(&mut *tx).await?;
        tx.commit().await?;

        // Use non-hardened path for receiving addresses (BIP44 standard)
        let path = format!("m/0/{}", index);
        let (address, pubkey) = self.derive_address(&path)?;
        
        self.record_address(&address.to_string(), &path, &pubkey.to_bytes(), false).await?;
        
        Ok(address)
    }

    /// Records a derived address in the database for future lookup.
    ///
    /// # Arguments
    ///
    /// * `address` - The string representation of the address.
    /// * `derivation_path` - The BIP32 path used to derive the address.
    /// * `pubkey` - The raw public key bytes.
    /// * `is_change` - `true` if this is an internal (change) address, `false` otherwise.
    ///
    /// # Note
    ///
    /// Uses `ON CONFLICT(address) DO NOTHING` to ensure idempotent inserts, preventing 
    /// errors if the same address is generated multiple times.
    pub async fn record_address(&self, address: &str, derivation_path: &str, pubkey: &[u8], is_change: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "INSERT INTO derived_addresses (address, derivation_path, public_key, is_change) 
             VALUES (?, ?, ?, ?) ON CONFLICT(address) DO NOTHING"
        )
        .bind(address)
        .bind(derivation_path)
        .bind(hex::encode(pubkey))
        .bind(is_change)
        .execute(&self.pool).await?;
        Ok(())
    }

    /// Retrieves the raw public key bytes for a previously derived address.
    ///
    /// # Arguments
    ///
    /// * `address` - The string representation of the address to look up.
    ///
    /// # Returns
    ///
    /// The raw public key bytes as a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not found in the database or if hex decoding fails.
    pub async fn get_public_key_for_address(&self, address: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let row = sqlx::query("SELECT public_key FROM derived_addresses WHERE address = ?")
            .bind(address)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let pubkey_hex: String = row.try_get(0)?;
            Ok(hex::decode(&pubkey_hex)?)
        } else {
            Err("Address not found in key manager".into())
        }
    }

    /// Derives the uncompressed public key bytes for a specific derivation path.
    ///
    /// # Arguments
    ///
    /// * `path_str` - The BIP32 derivation path string.
    ///
    /// # Returns
    ///
    /// A 65-byte array containing the uncompressed public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    pub fn derive_pubkey_bytes(&self, path_str: &str) -> Result<[u8; 65], Box<dyn std::error::Error + Send + Sync>> {
        let path: DerivationPath = path_str.parse()?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let child_xpub = self.master_xpub.derive_pub(&secp, &path)?;
        Ok(child_xpub.public_key.serialize_uncompressed())
    }
}

