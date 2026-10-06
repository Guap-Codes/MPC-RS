//! # Proactive Secret Sharing (Key Refresh)
//!
//! This module implements key rotation (refresh) for threshold keys. Refreshing
//! key shares updates the secret material held by each node without changing the
//! master public key, thereby providing forward secrecy and invalidating any
//! previously compromised shares.
//!
//! ## Production Strategy: n-of-n vs t-of-n
//! - **n-of-n Vaults**: The `cggmp21` crate natively supports the `key_refresh`
//!   protocol for non-threshold (n-out-of-n) settings. This module executes that
//!   protocol to update shares in-place.
//! - **t-of-n Vaults**: The `cggmp21` crate currently does not support threshold
//!   key refresh. For t-of-n vaults, the system enforces a **"Migration Rotation"**
//!   strategy:
//!   1. Generate a completely new key via DKG.
//!   2. Sign a transaction moving all funds from the old vault to the new vault.
//!   3. Retire the old key.
//!
//! This function will explicitly reject t-of-n refresh attempts to prevent
//! accidental misuse or protocol failure.

use cggmp21::{
    key_refresh::{PregeneratedPrimes, NonThresholdMsg},
    supported_curves::Secp256k1,
    ExecutionId, KeyShare,
    round_based::MpcParty,
};
use rand::rngs::OsRng;
use mpc_common::error::{MpcResult, MpcError};

pub type Cggmp21RefreshMsg = NonThresholdMsg<Secp256k1, sha2::Sha256, cggmp21::security_level::SecurityLevel128>;

/// Runs the CGGMP21 key refresh protocol for n-of-n vaults.
///
/// This function updates the local secret share and the auxiliary information
/// without altering the shared master public key, ensuring forward secrecy.
///
/// # Arguments
///
/// * `eid` - A unique execution ID for this specific protocol run.
/// * `key_share` - The current `KeyShare` held by the local node.
/// * `t` - The threshold of the vault.
/// * `n` - The total number of parties in the vault.
/// * `party` - The communication channel for exchanging refresh messages.
///
/// # Returns
///
/// A new `KeyShare` containing the refreshed secret material and updated aux info.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if `t < n` (threshold refresh is unsupported),
/// or if the cryptographic protocol fails.
/// Returns `MpcError::Internal` if the background thread for prime generation panics.
///
/// # Note
///
/// Like the initial aux info generation, prime generation for the refresh protocol
/// is offloaded to a blocking thread pool (`spawn_blocking`) to prevent starving
/// the Tokio async runtime.
pub async fn run_refresh<Del>(
    eid: ExecutionId<'_>,
    key_share: &KeyShare<Secp256k1>,
    t: u16,
    n: u16,
    party: MpcParty<Cggmp21RefreshMsg, Del>,
) -> MpcResult<KeyShare<Secp256k1>>
where
    Del: cggmp21::round_based::Delivery<Cggmp21RefreshMsg>,
{
    if t < n {
        return Err(MpcError::TssProtocol(
            "Threshold key refresh (t < n) is not supported by the cggmp21 crate. \
             Please perform a Migration Rotation (generate new vault and transfer funds).".into()
        ));
    }

    // Offload to blocking thread pool to prevent reactor starvation
    let pregenerated = tokio::task::spawn_blocking(|| {
        PregeneratedPrimes::<cggmp21::security_level::SecurityLevel128>::generate(&mut OsRng)
    })
    .await
    .map_err(|e| MpcError::Internal(format!("spawn_blocking failed: {}", e)))?;
    
    let new_share = cggmp21::key_refresh(eid, key_share, pregenerated)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| MpcError::TssProtocol(format!("n-of-n key refresh failed: {e}")))?;
        
    Ok(new_share)
}

