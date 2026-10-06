//! # Hardware Wallet Traits
//!
//! This module defines the core interfaces that hardware wallet implementations
//! must satisfy to be integrated into the MPC-RS signing workflow.

use async_trait::async_trait;
use crate::error::HwError;

/// A generic interface for a hardware wallet capable of cryptographic signing.
///
/// Implementors of this trait abstract away the specific transport mechanisms
/// (e.g., HID over USB, `WebUSB`, Bluetooth, or QR code scanning) and the
/// device-specific command sets (e.g., Ledger APDUs, Trezor Protobufs).
///
/// # Thread Safety
/// Implementations must be `Send` and `Sync` to allow safe sharing across
/// asynchronous tasks, though mutable operations (like `connect`) require
/// exclusive access via `&mut self`.
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait HwSigner: Send + Sync {
    /// Establishes a connection to the hardware wallet.
    ///
    /// This method handles the underlying transport initialization, such as
    /// opening a USB HID device or establishing a Bluetooth socket.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::DeviceNotFound`] if the device is not plugged in,
    /// or [`HwError::Connection`] if the transport fails to initialize.
    async fn connect(&mut self) -> Result<(), HwError>;

    /// Gracefully disconnects from the hardware wallet and releases resources.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::Communication`] if the device fails to acknowledge
    /// the disconnect command, though local resources should still be cleaned up.
    async fn disconnect(&mut self) -> Result<(), HwError>;

    /// Retrieves the public key associated with a specific BIP32/SLIP-0010 derivation path.
    ///
    /// # Arguments
    ///
    /// * `derivation_path` - The hierarchical derivation path (e.g., `"m/44'/60'/0'/0/0"`).
    /// * `display_on_device` - If `true`, the device should prompt the user to visually
    ///   verify the derived address on its physical screen before returning it. This is a 
    ///   critical security feature to prevent address spoofing by a compromised host machine.
    ///
    /// # Returns
    ///
    /// The raw bytes of the public key (e.g., 33-byte compressed secp256k1 or 32-byte ed25519).
    ///
    /// # Errors
    ///
    /// Returns [`HwError::InvalidResponse`] if the device returns a malformed key,
    /// or [`HwError::Communication`] if the request times out or is rejected by the user.
    async fn get_public_key(
        &self,
        derivation_path: &str,
        display_on_device: bool,
    ) -> Result<Vec<u8>, HwError>;

    /// Signs a pre-computed 32-byte message digest (e.g., a transaction hash or sighash).
    ///
    /// # Arguments
    ///
    /// * `derivation_path` - The hierarchical derivation path of the key to use for signing.
    /// * `digest` - The 32-byte cryptographic hash of the transaction or message to be signed.
    ///
    /// # Returns
    ///
    /// The raw signature bytes. The exact format (e.g., 64-byte raw ECDSA, 65-byte with recovery ID,
    /// or 64-byte `EdDSA`) depends on the curve and the specific device implementation.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::InvalidResponse`] if the signature is malformed,
    /// [`HwError::Unsupported`] if the curve or path is not supported, or
    /// [`HwError::Communication`] if the device fails to respond or the user rejects the prompt.
    async fn sign_digest(
        &self,
        derivation_path: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, HwError>;

    /// Checks if the device is still connected and responsive.
    ///
    /// This is typically implemented by sending a lightweight "ping" or "get version"
    /// command to the device. It is useful for detecting unexpected physical disconnections
    /// (e.g., a user accidentally unplugging the USB cable) before attempting a critical 
    /// signing operation.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::DeviceNotFound`] or [`HwError::Communication`] if the device
    /// is no longer reachable.
    async fn ping(&self) -> Result<(), HwError>;
}

