//! # Tron Protobuf Definitions
//!
//! This module contains minimal, hand-crafted Prost protobuf definitions that perfectly 
//! match the Tron network's wire format.
//!
//! ## Architectural Purpose
//! By defining only the specific messages required for transaction construction 
//! (`Transaction`, `TransferContract`, `TriggerSmartContract`), this module avoids 
//! the need to import and compile the massive, 2000+ line official Tron `.proto` files, 
//! significantly reducing build times and dependency bloat while maintaining 100% 
//! network compatibility.

use prost::Message;

/// Minimal Tron Transaction wrapper.
///
/// This struct represents the top-level transaction object that is serialized, 
/// hashed for signing, and ultimately broadcast to the network.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Transaction {
    /// The raw, unsigned transaction data.
    #[prost(message, optional, tag = "1")]
    pub raw_data: Option<transaction::Raw>,
    
    /// The array of ECDSA signatures. For MPC-RS, this will contain exactly one 65-byte signature.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub signature: Vec<Vec<u8>>,
}

pub mod transaction {
    use prost::Message;

    /// The raw, unsigned payload of a Tron transaction.
    ///
    /// This struct contains all the metadata required by the Tron Virtual Machine (TVM) 
    /// to validate and execute the transaction, including replay protection fields.
    #[derive(Clone, PartialEq, Eq, Message)]
    pub struct Raw {
        /// The last 2 bytes of the reference block number (big-endian). Used for replay protection.
        #[prost(bytes, tag = "1")]
        pub ref_block_bytes: Vec<u8>,
        
        /// The reference block number (legacy field, typically set to 0 when `ref_block_bytes` is used).
        #[prost(int64, tag = "3")]
        pub ref_block_num: i64,
        
        /// Bytes 8..16 of the reference block's ID hash. Used for replay protection.
        #[prost(bytes, tag = "4")]
        pub ref_block_hash: Vec<u8>,
        
        /// The expiration timestamp of the transaction in milliseconds. 
        /// Transactions are rejected by the network if the current block timestamp exceeds this value.
        #[prost(int64, tag = "8")]
        pub expiration: i64,
        
        /// The list of contracts to execute. Tron transactions typically contain exactly one contract.
        #[prost(message, repeated, tag = "11")]
        pub contract: Vec<super::Contract>,
        
        /// The timestamp when the transaction was created, in milliseconds.
        #[prost(int64, tag = "14")]
        pub timestamp: i64,
        
        /// The maximum fee (in SUN) the sender is willing to pay for this transaction.
        #[prost(int64, tag = "18")]
        pub fee_limit: i64,
    }
}

/// A wrapper for a specific contract execution within a Tron transaction.
///
/// In the Tron protobuf format, nested messages (like `google.protobuf.Any`) are 
/// serialized as raw bytes. The `parameter` field contains the protobuf-encoded 
/// payload of the specific contract type (e.g., `TransferContract`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Contract {
    /// The integer identifier of the contract type (e.g., 1 for Transfer, 31 for `TriggerSmartContract`).
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    
    /// The protobuf-encoded parameters specific to the contract type.
    #[prost(bytes, tag = "2")]
    pub parameter: Vec<u8>, 
}

/// The payload for a native TRX transfer (`TransferContract`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TransferContract {
    /// The 21-byte raw payload of the sender's address.
    #[prost(bytes, tag = "1")]
    pub owner_address: Vec<u8>,
    
    /// The 21-byte raw payload of the recipient's address.
    #[prost(bytes, tag = "2")]
    pub to_address: Vec<u8>,
    
    /// The amount of TRX to transfer, denominated in SUN (1 TRX = 1,000,000 SUN).
    #[prost(int64, tag = "3")]
    pub amount: i64,
}

/// The payload for a TRC-20 (or any smart contract) interaction (`TriggerSmartContract`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TriggerSmartContract {
    /// The 21-byte raw payload of the caller's address.
    #[prost(bytes, tag = "1")]
    pub owner_address: Vec<u8>,
    
    /// The 21-byte raw payload of the target smart contract's address.
    #[prost(bytes, tag = "2")]
    pub contract_address: Vec<u8>,
    
    /// The amount of TRX to send along with the contract call (typically 0 for pure ERC-20 transfers).
    #[prost(int64, tag = "3")]
    pub call_value: i64,
    
    /// The ABI-encoded calldata for the smart contract function call (e.g., `transfer(address,uint256)`).
    #[prost(bytes, tag = "4")]
    pub data: Vec<u8>,
}

/// Tron Contract Type Identifiers.
/// These constants map to the specific integer codes expected by the Tron network.
///
/// Identifier for a native TRX transfer.
pub const TRANSFER_CONTRACT: i32 = 1;

/// Identifier for a smart contract execution (used for TRC-20 transfers).
pub const TRIGGER_SMART_CONTRACT: i32 = 31;




