//! # Hardware Wallet Errors
//!
//! This module defines the unified error types used across all hardware wallet
//! implementations. By standardizing errors, the higher-level signing logic can
//! handle device failures, connection drops, and invalid responses consistently.

use thiserror::Error;

/// Represents all possible errors that can occur during hardware wallet operations.
///
/// This enum covers the full spectrum of failures, from physical device
/// disconnection to protocol-level communication errors and invalid device responses.
#[derive(Error, Debug)]
pub enum HwError {
    /// Returned when the hardware wallet is not detected on the system.
    ///
    /// # Examples
    /// - The device is physically unplugged.
    /// - Bluetooth is out of range or disabled.
    /// - Required OS-level USB permissions have not been granted.
    #[error("Device not found")]
    DeviceNotFound,

    /// Returned when the initial connection to the device fails.
    ///
    /// # Examples
    /// - USB HID interface fails to open.
    /// - Bluetooth pairing or socket connection is rejected.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Returned when an error occurs during data exchange with the device
    /// after a connection has been successfully established.
    ///
    /// # Examples
    /// - USB transfer timeout.
    /// - Malformed APDU response from a Ledger device.
    #[error("Communication error: {0}")]
    Communication(String),

    /// Returned when the device responds, but the payload is malformed,
    /// missing expected fields, or fails cryptographic validation.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Returned when a requested operation is not supported by the specific
    /// hardware wallet model or its current firmware version.
    ///
    /// # Examples
    /// - Attempting to sign a novel transaction type on an outdated firmware.
    /// - Requesting a derivation path for an unsupported curve (e.g., ed25519 on a legacy device).
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Returned for unexpected, unrecoverable, or internal state errors
    /// within the hardware wallet abstraction layer.
    #[error("Internal error: {0}")]
    Internal(String),
}


