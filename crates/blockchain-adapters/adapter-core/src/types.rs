use bitcoin::{OutPoint, TxOut};

/// Represents a spendable Unspent Transaction Output (UTXO).
///
/// This struct is primarily used by UTXO-based blockchain adapters (like Bitcoin) 
/// to track available funds that can be consumed as inputs in a new transaction.
#[derive(Debug, Clone)]
pub struct Utxo {
    /// The unique identifier of the UTXO, consisting of the previous transaction ID 
    /// and the output index within that transaction.
    pub outpoint: OutPoint,
    
    /// The actual transaction output, containing the locked script (address) and 
    /// the amount of funds available to be spent.
    pub tx_out: TxOut,
}

