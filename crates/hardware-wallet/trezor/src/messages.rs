//! # Trezor Protobuf Messages
//!
//! This module re-exports the specific Protobuf message definitions from the 
//! `trezor-client` crate that are required for building requests and parsing 
//! responses in the MPC-RS signing workflow.
//!
//! By centralizing these re-exports, we isolate the dependency on `trezor-client`'s 
//! internal module structure, making future upgrades or migrations easier to manage.

pub use trezor_client::protos::{
    // Bitcoin / Generic Key Management
    GetPublicKey, PublicKey,
    
    // Bitcoin Transaction Signing
    TxAck, TxRequest, SignTx,
    
    // Ethereum Key Management
    EthereumGetPublicKey, EthereumPublicKey, 
    
    // Ethereum Transaction Signing
    EthereumSignTx, EthereumTxRequest,
    
    // Generic Message Signing (used for raw digest signing)
    MessageSignature, SignMessage,
};

