//! # Tron RPC Client
//!
//! This module defines the trait and HTTP implementation for fetching real-time 
//! blockchain state from a Tron full node, specifically the block data required 
//! for transaction replay protection.

use adapter_core::error::AdapterError;
use async_trait::async_trait;
use serde::Deserialize;

/// A trait for fetching dynamic network state from a Tron node.
///
/// This abstraction allows the adapter to be tested with mock implementations 
/// and deployed with different RPC providers (e.g., `TronGrid`, private nodes).
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait TronRpcClient: Send + Sync {
    /// Fetches the data required to construct a valid Tron transaction.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. `ref_block_bytes`: The last 2 bytes of the current block number (big-endian).
    /// 2. `ref_block_hash`: Bytes 8 through 16 of the current block's ID (hex-decoded).
    /// 3. `expiration`: The transaction expiration timestamp in milliseconds (typically current block timestamp + 60 seconds).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the HTTP request fails, the response 
    /// is not valid JSON, or the block ID cannot be hex-decoded.
    async fn get_latest_block_data(&self) -> Result<(Vec<u8>, Vec<u8>, i64), AdapterError>;
}

/// An HTTP-based implementation of [`TronRpcClient`].
pub struct HttpTronRpcClient {
    client: reqwest::Client,
    full_node_url: String,
}

impl HttpTronRpcClient {
    /// Creates a new `HttpTronRpcClient` with a default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `full_node_url` - The base URL of the Tron full node (e.g., `https://api.trongrid.io`).
    #[must_use]
    pub fn new(full_node_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            full_node_url,
        }
    }
}

// Serde structures for parsing the `/wallet/getnowblock` JSON-RPC response.

#[derive(Deserialize)]
struct BlockHeader {
    raw_data: BlockRawData,
}

#[derive(Deserialize)]
struct BlockRawData {
    number: i64,
    #[serde(rename = "timestamp")]
    timestamp: i64,
}

#[derive(Deserialize)]
struct Block {
    #[serde(rename = "blockID")]
    block_id: String,
    block_header: BlockHeader,
}

#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
impl TronRpcClient for HttpTronRpcClient {
    async fn get_latest_block_data(&self) -> Result<(Vec<u8>, Vec<u8>, i64), AdapterError> {
        let url = format!("{}/wallet/getnowblock", self.full_node_url);
        let block: Block = self.client.post(&url).send().await
            .map_err(|e| AdapterError::Internal(format!("Tron RPC failed: {e}")))?
            .json().await
            .map_err(|e| AdapterError::Internal(format!("Tron RPC parse failed: {e}")))?;

        // ref_block_bytes is the last 2 bytes of the block number (big-endian)
        let block_num = block.block_header.raw_data.number;
        
        // Intentional truncation to get the lower 16 bits for replay protection
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::as_conversions)]
        let ref_block_bytes = (block_num as u16).to_be_bytes().to_vec();

        // ref_block_hash is bytes 8..16 of the blockID (hex decoded)
        let block_id_bytes = hex::decode(&block.block_id)
            .map_err(|e| AdapterError::Internal(format!("Invalid blockID: {e}")))?;
        let ref_block_hash = block_id_bytes.get(8..16).map_or_else(Vec::new, <[u8]>::to_vec);

        // Expiration is typically current block timestamp + 60 seconds (60,000 ms)
        let expiration = block.block_header.raw_data.timestamp.saturating_add(60_000);

        Ok((ref_block_bytes, ref_block_hash, expiration))
    }
}
