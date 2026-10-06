//! # Ledger APDU Command Builder
//!
//! This module provides utilities for constructing Application Protocol Data Units (APDUs)
//! required to communicate with Ledger hardware wallet applications.
//!
//! Ledger apps process transactions in a stateful, multi-step manner (especially Bitcoin),
//! requiring precise sequencing of `START_TRANSACTION`, `PROVIDE_INPUT`, `PROVIDE_OUTPUT`, 
//! and `SIGN_TRANSACTION` commands.

use ledger_apdu::APDUCommand;

/// A stateless builder for standard Ledger App APDU commands.
pub struct ApduBuilder;

impl ApduBuilder {
    // ==========================================
    // BITCOIN APP APDUs
    // ==========================================

    /// Builds an APDU to retrieve the Bitcoin public key for a given derivation path.
    ///
    /// # Arguments
    ///
    /// * `derivation` - The BIP32 derivation path encoded as a binary blob (u32 big-endian).
    /// * `display` - If `true`, the Ledger device will prompt the user to visually verify 
    ///   the address on its physical screen.
    ///
    /// # Returns
    ///
    /// An `APDUCommand` ready to be sent to the device.
    #[must_use]
    pub fn get_public_key_btc(derivation: &[u8], display: bool) -> APDUCommand<Vec<u8>> {
        let p1 = u8::from(display);
        APDUCommand {
            cla: 0xE0,
            ins: 0x40, // GET_PUBLIC_KEY
            p1,
            p2: 0x00,
            data: derivation.to_vec(),
        }
    }

    /// Step 1: Starts the Bitcoin transaction signing process.
    ///
    /// # Arguments
    ///
    /// * `version` - The transaction version (e.g., 2 for `SegWit`).
    /// * `num_inputs` - Total number of inputs in the transaction.
    /// * `num_outputs` - Total number of outputs in the transaction.
    /// * `locktime` - The transaction locktime.
    /// * `is_segwit` - `true` if this is a `SegWit` transaction (affects how the device hashes the data).
    #[must_use]
    pub fn start_transaction(
        version: u32,
        num_inputs: u32,
        num_outputs: u32,
        locktime: u32,
        is_segwit: bool,
    ) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&num_inputs.to_le_bytes());
        data.extend_from_slice(&num_outputs.to_le_bytes());
        data.extend_from_slice(&locktime.to_le_bytes());
        data.push(if is_segwit { 0x02 } else { 0x00 }); // 0x02 = Segwit, 0x00 = Legacy

        APDUCommand {
            cla: 0xE0,
            ins: 0x4A, // START_TRANSACTION
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }

    /// Step 2: Provides a single Bitcoin transaction input to the device.
    ///
    /// # Note
    /// This command may need to be called multiple times (chunked) if the input data 
    /// exceeds the Ledger's APDU payload size limit (typically 255 bytes).
    #[must_use]
    pub fn provide_input(
        input_index: u32,
        prevout_txid: &[u8; 32],
        prevout_vout: u32,
        prevout_script: &[u8],
        amount: u64,
        sequence: u32,
    ) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&input_index.to_le_bytes());
        data.extend_from_slice(prevout_txid); // 32 bytes, little-endian
        data.extend_from_slice(&prevout_vout.to_le_bytes());
        
        let script_len = u32::try_from(prevout_script.len()).unwrap_or(0);
        data.extend_from_slice(&script_len.to_le_bytes());
        data.extend_from_slice(prevout_script);
        
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&sequence.to_le_bytes());

        APDUCommand {
            cla: 0xE0,
            ins: 0x4B, // PROVIDE_INPUT
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }

    /// Step 3: Provides a single Bitcoin transaction output to the device.
    #[must_use]
    pub fn provide_output(
        output_index: u32,
        amount: u64,
        script_pubkey: &[u8],
    ) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&output_index.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        
        let script_len = u32::try_from(script_pubkey.len()).unwrap_or(0);
        data.extend_from_slice(&script_len.to_le_bytes());
        data.extend_from_slice(script_pubkey);

        APDUCommand {
            cla: 0xE0,
            ins: 0x4C, // PROVIDE_OUTPUT
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }

    /// Step 4: Finalizes and signs the Bitcoin transaction.
    ///
    /// # Arguments
    ///
    /// * `derivation_path` - The binary-encoded BIP32 path of the key to sign with.
    /// * `sighash_type` - The signature hash type (e.g., `0x01` for `SIGHASH_ALL`).
    #[must_use]
    pub fn sign_transaction_btc(
        derivation_path: &[u8],
        sighash_type: u32,
    ) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        let num_elements = u8::try_from(derivation_path.len() / 4).unwrap_or(0);
        data.push(num_elements);
        data.extend_from_slice(derivation_path);
        data.extend_from_slice(&sighash_type.to_le_bytes());

        APDUCommand {
            cla: 0xE0,
            ins: 0x4E, // SIGN_TRANSACTION
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }

    /// Signs a raw 32-byte digest using the Bitcoin App.
    ///
    /// # Note on MPC Repurposing
    /// The standard Ledger Bitcoin App uses this APDU (`ins: 0x42`) for "Sign Message", 
    /// which normally produces a BIP-322 message signature. However, in an MPC context, 
    /// this is repurposed to simply perform the raw ECDSA scalar multiplication over the 
    /// 32-byte protocol digest to generate a signature share, bypassing the standard 
    /// message hashing routine.
    #[must_use]
    pub fn sign_digest_btc(derivation: &[u8], digest: &[u8; 32]) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        let num_elements = u8::try_from(derivation.len() / 4).unwrap_or(0);
        data.push(num_elements);
        data.extend_from_slice(derivation);
        
        // Digest is strictly 32 bytes
        data.extend_from_slice(&32u32.to_le_bytes());
        data.extend_from_slice(digest);

        APDUCommand {
            cla: 0xE0,
            ins: 0x42, // SIGN_MESSAGE
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }

    // ==========================================
    // ETHEREUM APP APDUs
    // ==========================================

    /// Builds an APDU to retrieve the Ethereum public key for a given derivation path.
    #[must_use]
    pub fn get_public_key_eth(derivation: &[u8], display: bool) -> APDUCommand<Vec<u8>> {
        let p1 = u8::from(display);
        APDUCommand {
            cla: 0xE0,
            ins: 0x02, // GET_PUBLIC_KEY
            p1,
            p2: 0x00,
            data: derivation.to_vec(),
        }
    }

    /// Signs an Ethereum transaction hash or EIP-191/EIP-712 digest.
    ///
    /// # Note
    /// Unlike the Bitcoin app, the Ledger Ethereum App natively supports signing 
    /// raw 32-byte digests directly, making it ideal for MPC signature share generation.
    #[must_use]
    pub fn sign_digest_eth(derivation: &[u8], digest: &[u8; 32]) -> APDUCommand<Vec<u8>> {
        let mut data = Vec::new();
        let num_elements = u8::try_from(derivation.len() / 4).unwrap_or(0);
        data.push(num_elements);
        data.extend_from_slice(derivation);
        data.extend_from_slice(digest); // 32 bytes

        APDUCommand {
            cla: 0xE0,
            ins: 0x04, // SIGN_PERSONAL_MESSAGE or SIGN_TX
            p1: 0x00,
            p2: 0x00,
            data,
        }
    }
}
