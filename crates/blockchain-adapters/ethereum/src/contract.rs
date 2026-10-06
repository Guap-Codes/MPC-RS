//! # Ethereum Smart Contract Utilities
//!
//! This module provides utilities for interacting with Ethereum smart contracts,
//! specifically focusing on ABI encoding and constructing contract-call transactions.
//!
//! In the MPC-RS architecture, this module bridges the gap between high-level 
//! transfer requests and the low-level EVM calldata required to execute them.

use alloy_primitives::{Address, U256, Bytes, TxKind};
use alloy_consensus::{TxEip1559, SignableTransaction};
use alloy_rlp::Encodable;
use adapter_core::error::AdapterError;

/// Encodes the calldata for a standard ERC-20 `transfer(address,uint256)` call.
///
/// This function manually constructs the Application Binary Interface (ABI) 
/// encoded payload required by the EVM, ensuring strict compliance with the 
/// ERC-20 specification.
///
/// # Arguments
///
/// * `to` - The destination `Address` receiving the tokens.
/// * `value` - The `U256` amount of tokens to transfer (in the token's base units, e.g., wei or decimals).
///
/// # Returns
///
/// A `Bytes` object containing the 68-byte ABI-encoded calldata:
/// - Bytes 0-3: Function selector (`0xa9059cbb` for `transfer`).
/// - Bytes 4-35: 32-byte left-padded destination address.
/// - Bytes 36-67: 32-byte big-endian encoded transfer amount.
#[must_use]
pub fn encode_erc20_transfer_calldata(to: Address, value: U256) -> Bytes {
    // 1. Function selector for `transfer(address,uint256)`
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; 
    
    // 2. Left-pad the 20-byte address to 32 bytes as per EVM ABI spec
    let mut padded_addr = [0u8; 32];
    padded_addr[12..].copy_from_slice(to.as_slice());
    data.extend_from_slice(&padded_addr);
    
    // 3. Append the 32-byte big-endian representation of the value
    let amount_bytes = value.to_be_bytes::<32>();
    data.extend_from_slice(&amount_bytes);
    
    Bytes::from(data)
}

/// Builds an unsigned EIP-1559 transaction targeting an ERC-20 contract's `transfer` function.
///
/// This is a specialized wrapper around [`build_eip1559_tx`] that automatically 
/// handles the ERC-20 calldata encoding, setting the contract address as the 
/// transaction recipient and the native ETH value to zero.
///
/// # Arguments
///
/// * `contract_address` - The address of the ERC-20 token contract.
/// * `to` - The destination address receiving the tokens.
/// * `value` - The amount of tokens to transfer.
/// * `nonce` - The sender's current transaction nonce.
/// * `gas_limit` - The maximum gas allowed for the transaction.
/// * `max_fee_per_gas` - The maximum total fee per gas the sender is willing to pay.
/// * `max_priority_fee_per_gas` - The maximum tip to the block producer.
/// * `chain_id` - The EIP-155 chain ID to prevent replay attacks.
///
/// # Returns
///
/// A tuple containing:
/// 1. The unsigned transaction serialized as EIP-2718 typed RLP bytes (prefixed with `0x02`).
/// 2. The 32-byte EIP-1559 signature hash (sighash) that the MPC nodes must sign.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the underlying RLP encoding or signature hash 
/// computation fails (though this is rare for valid inputs).
#[allow(clippy::too_many_arguments)]
pub fn build_erc20_transfer(
    contract_address: Address,
    to: Address,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    chain_id: u64,
) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
    let data = encode_erc20_transfer_calldata(to, value);

    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(contract_address),
        value: U256::ZERO, // Native ETH value is zero for ERC-20 transfers
        input: data,
        #[allow(clippy::default_trait_access)]
        access_list: Default::default(),
    };

    let sighash = tx.signature_hash();
    
    // EIP-2718 Typed Transaction Envelope: 0x02 || RLP(TxEip1559)
    let mut unsigned_rlp = Vec::new();
    unsigned_rlp.push(0x02);
    tx.encode(&mut unsigned_rlp);

    Ok((unsigned_rlp, sighash.0))
}




