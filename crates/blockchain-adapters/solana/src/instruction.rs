//! # Solana Instruction Builders
//!
//! This module provides utilities for constructing Solana instructions, 
//! specifically for native SOL transfers and SPL Token transfers.
//!
//! In the MPC-RS architecture, these builders encapsulate the chain-specific 
//! logic required to interact with the Solana runtime, including the automatic 
//! creation of Associated Token Accounts (ATAs) to ensure robust, idempotent transfers.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::instruction::Instruction;
use solana_system_interface::instruction as system_instruction; 
use spl_associated_token_account_interface::{
    address::get_associated_token_address,
    instruction::create_associated_token_account_idempotent,
};
use spl_token_interface::instruction::transfer_checked;
use spl_token_interface::id as token_program_id;
use adapter_core::error::AdapterError;

/// Builds a native SOL transfer instruction.
///
/// # Arguments
///
/// * `from` - The source public key (the MPC vault).
/// * `to` - The destination public key.
/// * `lamports` - The amount of SOL to transfer, denominated in lamports (1 SOL = 1,000,000,000 lamports).
///
/// # Returns
///
/// A Solana [`Instruction`] ready to be included in a transaction message.
#[must_use]
pub fn build_sol_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    system_instruction::transfer(from, to, lamports)
}

/// Builds an SPL Token transfer instruction, including idempotent ATA creation.
///
/// This function constructs a sequence of two instructions:
/// 1. `create_associated_token_account_idempotent`: Ensures the recipient has a valid 
///    Associated Token Account (ATA) for the specified mint. If it exists, this 
///    instruction succeeds silently without error. If it does not, it is created 
///    and funded with the required rent exemption.
/// 2. `transfer_checked`: Executes the actual token transfer, verifying the decimals 
///    to prevent precision loss or accidental transfers of the wrong magnitude.
///
/// # Arguments
///
/// * `payer` - The public key that will pay the rent for the new ATA (if created). Typically the sender.
/// * `authority` - The public key that owns the source tokens and will sign the transfer.
/// * `mint` - The public key of the SPL Token mint.
/// * `to_wallet` - The destination wallet public key.
/// * `amount` - The amount of tokens to transfer, in the token's base units (e.g., 1,000,000 for 1 USDC).
/// * `decimals` - The number of decimals for the token mint, used for the `transfer_checked` validation.
///
/// # Returns
///
/// A `Vec<Instruction>` containing the ATA creation (if needed) and the transfer instruction, 
/// in the correct execution order.
///
/// # Errors
///
/// Returns an [`AdapterError::Internal`] if the `transfer_checked` instruction fails to build 
/// (e.g., due to invalid parameter combinations).
pub fn build_spl_transfer(
    payer: &Pubkey,
    authority: &Pubkey,
    mint: &Pubkey,
    to_wallet: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Result<Vec<Instruction>, AdapterError> {
    let source_ata = get_associated_token_address(authority, mint);
    let dest_ata = get_associated_token_address(to_wallet, mint);
    
    // Idempotent ATA creation for the recipient using the interface crate
    let create_ata_ix = create_associated_token_account_idempotent(
        payer,
        to_wallet,
        mint,
        &token_program_id(),
    );

    // Transfer checked using the interface crate
    let transfer_ix = transfer_checked(
        &token_program_id(),
        &source_ata,
        mint,
        &dest_ata,
        authority,
        &[], // No multi-sig signers
        amount,
        decimals,
    ).map_err(|e| AdapterError::Internal(format!("Failed to build SPL instruction: {e}")))?;
    
    // Order matters: Create ATA first, then transfer
    Ok(vec![create_ata_ix, transfer_ix])
}

