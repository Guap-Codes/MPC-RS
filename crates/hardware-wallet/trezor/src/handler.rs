//! # Trezor Handler Implementation
//!
//! This module implements the [`HwSigner`] trait for Trezor devices. It maps 
//! high-level signing requests to the specific Protobuf messages required by 
//! the Trezor firmware, handling chain-specific nuances and device interaction loops.

use async_trait::async_trait;
use hw_common::traits::HwSigner;
use hw_common::error::HwError;
use super::transport::TrezorTransport;
use trezor_client::client::handle_interaction;
use trezor_client::protos::{GetPublicKey, EthereumGetPublicKey, SignMessage, MessageSignature};

/// The target blockchain network for the Trezor operation.
///
/// This dictates which specific Protobuf message types and derivation path 
/// validation rules are applied during key generation and signing.
#[derive(Clone, Debug)]
pub enum Chain {
    /// Bitcoin and Bitcoin-compatible networks (e.g., Regtest, Testnet).
    Bitcoin,
    /// Ethereum and EVM-compatible networks.
    Ethereum,
}

/// The main state machine managing a Trezor device session.
pub struct TrezorApp {
    transport: Option<TrezorTransport>,
    chain: Chain,
}

impl TrezorApp {
    /// Creates a new `TrezorApp` instance for the specified blockchain.
    ///
    /// Note: This does not connect to the device. Call [`connect`] to establish 
    /// the USB or UDP session.
    #[must_use]
    pub const fn new(chain: Chain) -> Self {
        Self { transport: None, chain }
    }
}

#[async_trait]
impl HwSigner for TrezorApp {
    /// Establishes a connection to a physical Trezor device via `WebUSB`.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::Connection`] if the device is not found, unplugged, 
    /// or fails to initialize.
    async fn connect(&mut self) -> Result<(), HwError> {
        // Connect to USB device by default. 
        let transport = TrezorTransport::new_usb(false)?;
        self.transport = Some(transport);
        Ok(())
    }

    /// Gracefully disconnects from the device by dropping the transport layer.
    async fn disconnect(&mut self) -> Result<(), HwError> {
        self.transport = None;
        Ok(())
    }

    /// Retrieves the public key for a given BIP32 derivation path.
    ///
    /// # Arguments
    ///
    /// * `derivation_path` - A string representing the path (e.g., `"m/44'/0'/0'/0/0"`).
    /// * `display` - If `true`, the Trezor device will prompt the user to visually 
    ///   confirm the derived address on its physical screen, mitigating host-compromise attacks.
    ///
    /// # Returns
    ///
    /// The raw, uncompressed or compressed public key bytes (depending on the chain).
    ///
    /// # Errors
    ///
    /// Returns [`HwError::DeviceNotFound`] if not connected.
    /// Returns [`HwError::InvalidResponse`] if the derivation path is malformed, 
    /// the device rejects the request, or the public key is missing from the response.
    async fn get_public_key(
        &self,
        derivation_path: &str,
        display: bool,
    ) -> Result<Vec<u8>, HwError> {
        let transport = self.transport.as_ref().ok_or(HwError::DeviceNotFound)?;
        let mut client = transport.client();
        
        let res = match self.chain {
            Chain::Bitcoin => {
                let mut req = GetPublicKey::new();
                req.address_n = parse_derivation(derivation_path)?;
                req.set_show_display(display);
                
                let resp = client.call(req, Box::new(|_, m: trezor_client::protos::PublicKey| Ok(m)))
                    .map_err(|e| HwError::InvalidResponse(e.to_string()))?;
                
                let resp = handle_interaction(resp).map_err(|e| HwError::InvalidResponse(e.to_string()))?;
                
                // MessageField only implements Deref, so we must clone to get an owned Option
                resp.node.public_key.clone().ok_or_else(|| HwError::InvalidResponse("missing public key".into()))
            }
            Chain::Ethereum => {
                let mut req = EthereumGetPublicKey::new();
                req.address_n = parse_derivation(derivation_path)?;
                req.set_show_display(display);
                
                let resp = client.call(req, Box::new(|_, m: trezor_client::protos::EthereumPublicKey| Ok(m)))
                    .map_err(|e| HwError::InvalidResponse(e.to_string()))?;
                let resp = handle_interaction(resp).map_err(|e| HwError::InvalidResponse(e.to_string()))?;
                
                // MessageField only implements Deref, so we must clone to get an owned Option
                resp.node.public_key.clone().ok_or_else(|| HwError::InvalidResponse("missing public key".into()))
            }
        };
        
        drop(client);
        res
    }

    /// Signs a pre-computed 32-byte message digest (e.g., a transaction sighash).
    ///
    /// # Arguments
    ///
    /// * `derivation_path` - The BIP32 path of the key to use for signing.
    /// * `digest` - The exact 32-byte hash to be signed.
    ///
    /// # Returns
    ///
    /// The raw signature bytes (typically 64 or 65 bytes, depending on the chain and firmware).
    ///
    /// # Errors
    ///
    /// Returns [`HwError::DeviceNotFound`] if not connected.
    /// Returns [`HwError::InvalidResponse`] if the device rejects the signing request 
    /// (e.g., user cancels on device) or the signature is missing from the response.
    async fn sign_digest(
        &self,
        derivation_path: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, HwError> {
        let transport = self.transport.as_ref().ok_or(HwError::DeviceNotFound)?;
        let mut client = transport.client();
        
        let mut req = SignMessage::new();
        req.address_n = parse_derivation(derivation_path)?;
        req.set_message(digest.to_vec());
        
        let resp = client.call(req, Box::new(|_, m: MessageSignature| Ok(m)))
            .map_err(|e| HwError::InvalidResponse(e.to_string()))?;
        let resp = handle_interaction(resp).map_err(|e| HwError::InvalidResponse(e.to_string()))?;
        
        // resp is owned, so we can move the signature field directly without cloning
        let sig = resp.signature.ok_or_else(|| HwError::InvalidResponse("missing signature".into()));
        drop(client);
        sig
    }

    /// Checks if the device is still connected and responsive.
    ///
    /// This is achieved by requesting the device's `Features`, which is a 
    /// lightweight operation that does not require user interaction.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::DeviceNotFound`] if the transport is dropped.
    /// Returns [`HwError::InvalidResponse`] if the device fails to respond 
    /// (e.g., it was physically unplugged).
    async fn ping(&self) -> Result<(), HwError> {
        let transport = self.transport.as_ref().ok_or(HwError::DeviceNotFound)?;
        let mut client = transport.client();
        
        let req = trezor_client::protos::GetFeatures::new();
        let resp = client.call(req, Box::new(|_, m: trezor_client::protos::Features| Ok(m)))
            .map_err(|e| HwError::InvalidResponse(e.to_string()))?;
        let res = handle_interaction(resp).map_err(|e| HwError::InvalidResponse(e.to_string())).map(|_| ());
        
        drop(client);
        res
    }
}

/// Parses a BIP32 derivation path string into a vector of u32 indices.
///
/// # Format
///
/// Expects a string starting with `"m/"`, followed by slash-separated indices.
/// Hardened indices are denoted by a trailing apostrophe (`'`) or `h` (though 
/// this implementation specifically checks for `'`).
///
/// # Example
///
/// `"m/44'/0'/0'/0/0"` -> `[0x8000002C, 0x80000000, 0x80000000, 0, 0]`
///
/// # Errors
///
/// Returns [`HwError::InvalidResponse`] if the path does not start with `"m/"`, 
/// or if any segment cannot be parsed as a valid `u32`.
fn parse_derivation(path: &str) -> Result<Vec<u32>, HwError> {
    let stripped_path = path.strip_prefix("m/").ok_or_else(|| {
        HwError::InvalidResponse("invalid derivation path: must start with 'm/'".into())
    })?;
    
    stripped_path
        .split('/')
        .map(|part| {
            if let Some(stripped) = part.strip_suffix('\'') {
                // Hardened derivation: set the 31st bit (0x8000_0000)
                let val: u32 = stripped
                    .parse()
                    .map_err(|_| HwError::InvalidResponse(format!("parse error in hardened path segment: {part}")))?;
                Ok(val | 0x8000_0000)
            } else {
                // Normal derivation
                part.parse().map_err(|_| HwError::InvalidResponse(format!("parse error in path segment: {part}")))
            }
        })
        .collect()
}
