//! # Ledger App State Machine
//!
//! This module implements the [`HwSigner`] trait for Ledger devices, managing the 
//! connection lifecycle and routing high-level signing requests to the appropriate 
//! chain-specific APDU builders.

use async_trait::async_trait;
use hw_common::traits::HwSigner;
use hw_common::error::HwError;
use super::transport::LedgerTransport;
use super::apdu::ApduBuilder;

/// The target blockchain network for the Ledger operation.
#[derive(Clone, Debug)]
pub enum Chain {
    /// Bitcoin and Bitcoin-compatible networks.
    Bitcoin,
    /// Ethereum and EVM-compatible networks.
    Ethereum,
}

/// The main state machine managing a Ledger device session.
pub struct LedgerApp {
    transport: Option<LedgerTransport>,
    chain: Chain,
}

impl LedgerApp {
    /// Creates a new `LedgerApp` instance for the specified blockchain.
    ///
    /// Note: This does not connect to the device. Call [`connect`] to establish 
    /// the HID session.
    #[must_use]
    pub const fn new(chain: Chain) -> Self {
        Self { transport: None, chain }
    }
}

#[async_trait]
impl HwSigner for LedgerApp {
    /// Establishes a connection to the first available Ledger device via USB HID.
    async fn connect(&mut self) -> Result<(), HwError> {
        self.transport = Some(LedgerTransport::new()?);
        Ok(())
    }

    /// Gracefully disconnects from the device by dropping the transport layer.
    async fn disconnect(&mut self) -> Result<(), HwError> {
        self.transport = None;
        Ok(())
    }

    /// Retrieves the public key for a given BIP32 derivation path.
    async fn get_public_key(
        &self,
        derivation_path: &str,
        display: bool,
    ) -> Result<Vec<u8>, HwError> {
        // Clone the transport to get an owned handle for spawn_blocking
        let transport = self.transport.clone().ok_or(HwError::DeviceNotFound)?;
        let derivation = Self::parse_derivation(derivation_path)?;

        let apdu = match self.chain {
            Chain::Bitcoin => ApduBuilder::get_public_key_btc(&derivation, display),
            Chain::Ethereum => ApduBuilder::get_public_key_eth(&derivation, display),
        };

        let resp = tokio::task::spawn_blocking(move || {
            transport.exchange(&apdu)
        })
        .await
        .map_err(|e| HwError::Internal(e.to_string()))?
        .map_err(|e| HwError::Communication(e.to_string()))?;

        // Bitcoin returns [length, pubkey...], Ethereum returns [pubkey...]
        Ok(match self.chain {
            Chain::Bitcoin => resp.data().get(1..).unwrap_or(&[]).to_vec(),
            Chain::Ethereum => resp.data().to_vec(),
        })
    }

    /// Signs a pre-computed 32-byte message digest.
    async fn sign_digest(
        &self,
        derivation_path: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, HwError> {
        let transport = self.transport.clone().ok_or(HwError::DeviceNotFound)?;
        let derivation = Self::parse_derivation(derivation_path)?;

        let apdu = match self.chain {
            Chain::Bitcoin => ApduBuilder::sign_digest_btc(&derivation, digest),
            Chain::Ethereum => ApduBuilder::sign_digest_eth(&derivation, digest),
        };

        let resp = tokio::task::spawn_blocking(move || {
            transport.exchange(&apdu)
        })
        .await
        .map_err(|e| HwError::Internal(e.to_string()))?
        .map_err(|e| HwError::Communication(e.to_string()))?;

        Ok(resp.data().to_vec())
    }

    /// Checks if the device is still connected and responsive.
    async fn ping(&self) -> Result<(), HwError> {
        let transport = self.transport.clone().ok_or(HwError::DeviceNotFound)?;
        
        // Generic GET_APP_VERSION or similar ping command
        let apdu = ledger_apdu::APDUCommand {
            cla: 0xE0,
            ins: 0x01,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };
        
        let resp = tokio::task::spawn_blocking(move || {
            transport.exchange(&apdu)
        })
        .await
        .map_err(|e| HwError::Internal(e.to_string()))?
        .map_err(|e| HwError::Communication(e.to_string()))?;
        
        if resp.retcode() == 0x9000 {
            Ok(())
        } else {
            Err(HwError::Connection("unexpected response".into()))
        }
    }
}

impl LedgerApp {
    /// Converts a derivation path string (e.g., `"m/44'/60'/0'/0/0"`) into the 
    /// binary blob format expected by Ledger apps.
    ///
    /// # Format
    ///
    /// Each path segment is encoded as a 32-bit big-endian integer. If the segment 
    /// is hardened (ends with `'`), the `0x8000_0000` bit is set.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::InvalidResponse`] if the path does not start with `"m/"` 
    /// or if a segment cannot be parsed as a valid `u32`.
    fn parse_derivation(path: &str) -> Result<Vec<u8>, HwError> {
        let mut bytes = vec![];
        
        let stripped_path = path.strip_prefix("m/").ok_or_else(|| {
            HwError::InvalidResponse("invalid derivation path: must start with 'm/'".into())
        })?;
        
        let parts = stripped_path.split('/');
        for part in parts {
            let hardened = part.ends_with('\'');
            let num_str = if hardened {
                part.strip_suffix('\'').unwrap_or(part)
            } else {
                part
            };
            
            let num: u32 = num_str.parse().map_err(|_| {
                if hardened {
                    HwError::InvalidResponse(format!("parse error in hardened path segment: {part}"))
                } else {
                    HwError::InvalidResponse(format!("parse error in path segment: {part}"))
                }
            })?;
            
            let num = if hardened { num | 0x8000_0000 } else { num };
            bytes.extend_from_slice(&num.to_be_bytes());
        }
        Ok(bytes)
    }
} 
