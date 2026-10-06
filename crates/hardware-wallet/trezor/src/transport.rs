//! # Trezor Transport Layer
//!
//! This module manages the physical or emulated connection to the Trezor device.
//! It handles device discovery, connection initialization, and provides thread-safe 
//! access to the underlying Protobuf client.

use hw_common::error::HwError;
use trezor_client::client::{trezor_with_transport, Trezor};
use trezor_client::transport::{connect, udp::UdpTransport, webusb::WebUsbTransport, Transport};
use std::sync::Mutex;

/// A thread-safe wrapper around the `trezor_client::Trezor` client.
///
/// # Interior Mutability
/// The underlying `Trezor` client requires mutable access to send and receive 
/// Protobuf messages. By wrapping it in a `std::sync::Mutex`, we allow the 
/// [`HwSigner`] trait methods (which take `&self`) to safely interact with the 
/// device concurrently from an async runtime.
pub struct TrezorTransport {
    client: Mutex<Trezor>,
}

impl TrezorTransport {
    /// Connects to a physical Trezor device via `WebUSB`.
    ///
    /// # Arguments
    ///
    /// * `debug` - If `true`, enables verbose logging of the USB transport layer.
    ///
    /// # Returns
    ///
    /// An initialized `TrezorTransport` ready to send Protobuf messages.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::Connection`] if:
    /// - No Trezor devices are detected on the USB bus.
    /// - The OS denies permission to open the USB interface.
    /// - The device fails to initialize (e.g., it is locked or in bootloader mode).
    pub fn new_usb(debug: bool) -> Result<Self, HwError> {
        let devices = WebUsbTransport::find_devices(debug)
            .map_err(|e| HwError::Connection(format!("Failed to find USB devices: {e}")))?;

        let device = devices.into_iter().next().ok_or_else(|| {
            HwError::Connection("No Trezor device found. Is it plugged in and unlocked?".to_string())
        })?;

        let transport = connect(&device)
            .map_err(|e| HwError::Connection(format!("Failed to connect to device: {e}")))?;

        let mut client = trezor_with_transport(device.model, transport);
        client.init_device(None)
            .map_err(|e| HwError::Connection(format!("Failed to initialize device: {e}")))?;

        Ok(Self { client: Mutex::new(client) })
    }

    /// Connects to a Trezor emulator (`trezor-core`) via UDP.
    ///
    /// This is primarily used for automated integration testing without requiring 
    /// physical hardware.
    ///
    /// # Arguments
    ///
    /// * `debug` - If `true`, enables verbose logging of the UDP transport layer.
    /// * `path` - An optional custom UDP address (e.g., `"127.0.0.1:21324"`). 
    ///   If `None`, defaults to the standard Trezor emulator port.
    ///
    /// # Returns
    ///
    /// An initialized `TrezorTransport` connected to the emulator.
    ///
    /// # Errors
    ///
    /// Returns [`HwError::Connection`] if the emulator is not running or the 
    /// UDP socket fails to connect.
    pub fn new_udp(debug: bool, path: Option<&str>) -> Result<Self, HwError> {
        let devices = UdpTransport::find_devices(debug, path)
            .map_err(|e| HwError::Connection(format!("Failed to find UDP devices: {e}")))?;

        let device = devices.into_iter().next().ok_or_else(|| {
            HwError::Connection("No Trezor emulator found. Is it running?".to_string())
        })?;

        let transport = connect(&device)
            .map_err(|e| HwError::Connection(format!("Failed to connect to emulator: {e}")))?;

        let mut client = trezor_with_transport(device.model, transport);
        client.init_device(None)
            .map_err(|e| HwError::Connection(format!("Failed to initialize device: {e}")))?;

        Ok(Self { client: Mutex::new(client) })
    }

    /// Acquires a locked reference to the inner client to make Protobuf calls.
    ///
    /// # Note
    ///
    /// This method will panic if the `Mutex` is poisoned (i.e., if a previous 
    /// thread panicked while holding the lock). In a production system, this 
    /// indicates a catastrophic failure in the transport layer, and the application 
    /// should likely be restarted.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex guarding the client is poisoned.
    #[allow(clippy::expect_used)]
    pub fn client(&self) -> std::sync::MutexGuard<'_, Trezor> {
        self.client.lock().expect("Trezor client mutex poisoned")
    }
}