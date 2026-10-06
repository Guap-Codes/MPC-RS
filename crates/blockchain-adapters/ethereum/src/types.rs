//! # Ethereum Type Aliases
//!
//! This module provides domain-specific type aliases for core Ethereum data structures.
//! 
//! ## Architectural Purpose
//! By aliasing types from the underlying `alloy` crates, this module serves two critical 
//! purposes in the MPC-RS architecture:
//! 1. **Domain Clarity**: It makes the codebase more readable by explicitly stating the 
//!    intended use of a type (e.g., `EthereumAddress` vs a generic `Address`).
//! 2. **Decoupling**: It creates a clean abstraction boundary. If the underlying 
//!    cryptographic or consensus library changes in the future, only this file needs 
//!    to be updated, rather than refactoring the entire adapter codebase.

use alloy_primitives::{Address, B256, Signature, U256};
use alloy_consensus::{TxEip1559, TxEnvelope};

/// An unsigned EIP-1559 Ethereum transaction.
///
/// This type represents the core transaction payload before any cryptographic 
/// signature is applied. In the MPC-RS workflow, this is the structure that 
/// gets serialized into RLP format to compute the 32-byte signature hash (sighash) 
/// that the MPC nodes will sign.
pub type EthereumTransaction = TxEip1559;

/// A fully signed, network-ready Ethereum transaction.
///
/// This is an enum wrapper (`TxEnvelope`) that can encapsulate Legacy, EIP-2930, 
/// or EIP-1559 transactions. In this adapter, it specifically represents an 
/// EIP-1559 transaction that has been signed by the MPC threshold signature 
/// ceremony and is ready to be broadcast via `eth_sendRawTransaction`.
pub type EthereumSignedTransaction = TxEnvelope;

/// A standard 65-byte Ethereum ECDSA signature.
///
/// This represents the cryptographic proof of authorization for a transaction. 
/// It consists of the `r` and `s` scalar values (32 bytes each) and the `v` 
/// recovery ID (1 byte, normalized to 0 or 1 for EIP-1559), which allows 
/// the network to recover the signer's public key and verify the transaction.
pub type EthereumSignature = Signature;

/// A 20-byte Ethereum address.
///
/// Represents an Externally Owned Account (EOA) or a Smart Contract address 
/// on the Ethereum network. It is derived from the last 20 bytes of the 
/// Keccak-256 hash of the uncompressed secp256k1 public key.
pub type EthereumAddress = Address;

/// A 32-byte (256-bit) cryptographic hash.
///
/// Used extensively throughout the Ethereum protocol to represent transaction 
/// hashes (TXIDs), block hashes, and signature digests (sighashes). In the 
/// context of this adapter, it primarily represents the Keccak-256 hash of 
/// the signed transaction payload.
pub type EthereumHash = B256;

/// A 256-bit unsigned integer.
///
/// The standard numeric type for representing large values in the Ethereum 
/// Virtual Machine (EVM). It is used for native ETH balances (in wei), 
/// gas prices (max fee per gas), gas limits, and ERC-20 token amounts.
pub type EthereumU256 = U256;


