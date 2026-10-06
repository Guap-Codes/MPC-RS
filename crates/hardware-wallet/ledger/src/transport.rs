//! # Ledger HID Transport Layer
//!
//! This module manages the physical USB HID connection to the Ledger device.
//! It provides a thread-safe, cloneable wrapper around the underlying 
//! `ledger-transport-hid` library, enabling safe usage within asynchronous Rust runtimes.

use ledger_transport_hid::hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use std::sync::{Arc, Mutex};
use hw_common::error::HwError;
use ledger_apdu::{APDUAnswer, APDUCommand};

/// A thread-safe, cloneable wrapper around the Ledger HID transport.
///
/// # Interior Mutability
/// The underlying `TransportNativeHID` requires mutable access to send and receive 
/// APDU commands. By wrapping it in an `Arc<Mutex<...>>`, we allow the transport 
/// to be cloned and shared across multiple `tokio::task::spawn_blocking` threads 
/// without violating Rust's borrowing rules.
#[derive(Clone)] 
pub struct LedgerTransport {
    inner: Arc<Mutex<TransportNativeHID>>, 
}

impl LedgerTransport {
    /// Opens a connection to the first available Ledger device via USB HID.
    ///
    /// # Returns
    ///
    /// An initialized `LedgerTransport` ready to exchange APDUs.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::Connection`] if the OS-level HID API fails to initialize.
    /// Returns [`HwError::DeviceNotFound`] if no Ledger device is detected on the USB bus 
    /// (e.g., it is unplugged, locked, or permissions are denied).
    pub fn new() -> Result<Self, HwError> {
        let hidapi = HidApi::new()
            .map_err(|e| HwError::Connection(e.to_string()))?;
        let transport = TransportNativeHID::new(&hidapi)
            .map_err(|_| HwError::DeviceNotFound)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(transport)), 
        })
    }

    /// Exchanges an APDU command with the Ledger device and returns the response.
    ///
    /// # Arguments
    ///
    /// * `apdu` - The `APDUCommand` to send to the device.
    ///
    /// # Returns
    ///
    /// An `APDUAnswer` containing the response data and the 2-byte return code (e.g., `0x9000` for success).
    ///
    /// # Errors
    ///
    /// Returns a `LedgerHIDError` if the underlying HID transport fails to send or receive the APDU.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex guarding the HID transport is poisoned (i.e., a thread panicked while holding the lock).
    ///
    /// # Note
    ///
    /// This method acquires a `Mutex` lock. It is designed to be called from within 
    /// `tokio::task::spawn_blocking` to prevent blocking the async executor while 
    /// waiting for the user to interact with the physical device.
    #[allow(clippy::expect_used)]
    pub fn exchange(
        &self,
        apdu: &APDUCommand<Vec<u8>>,
    ) -> Result<APDUAnswer<Vec<u8>>, ledger_transport_hid::LedgerHIDError> {
        let transport = self.inner.lock().expect("Ledger transport mutex poisoned");
        transport.exchange(apdu)
    }
}
