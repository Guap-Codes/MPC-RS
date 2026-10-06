//! # CGGMP21 Distributed Key Generation (DKG)
//!
//! This module implements the CGGMP21 protocol for secp256k1 curves, which is the
//! foundation for threshold ECDSA signing in the MPC-RS system (used for Bitcoin,
//! Ethereum, and Tron).
//!
//! ## Auxiliary Information Reuse
//! CGGMP21 requires a computationally expensive "Auxiliary Information" generation
//! phase (generating Paillier keys and Ring-Pedersen parameters for zero-knowledge proofs).
//! This module separates `run_aux_info_gen` from `run_dkg` so that the aux info can be
//! generated once and reused across multiple DKG sessions for the same node, significantly
//! reducing the time required to provision new vaults.

use cggmp21::{
    aux_info_gen, keygen,
    supported_curves::Secp256k1,
    key_share::{AuxInfo, AnyKeyShare}, 
    ExecutionId, KeyShare, PregeneratedPrimes,
    round_based::MpcParty,
    keygen::ThresholdMsg,
    key_refresh::AuxOnlyMsg, 
};
use rand::rngs::OsRng;
use mpc_common::{
    types::{Curve, EncryptedShare, HsmIdentifier, PartyId, PublicKey, ShareMetadata},
    error::MpcResult,
};

// --- TYPE ALIASES FOR READABILITY ---
type Cggmp21KeygenMsg = ThresholdMsg<Secp256k1, cggmp21::security_level::SecurityLevel128, sha2::Sha256>;
type Cggmp21AuxMsg = AuxOnlyMsg<sha2::Sha256, cggmp21::security_level::SecurityLevel128>;
type Cggmp21KeyShare = KeyShare<Secp256k1>;
// ------------------------------------

/// Runs the CGGMP21 Auxiliary Information Generation protocol.
///
/// This is a one-time, computationally intensive setup phase that generates the
/// Paillier keys and Ring-Pedersen parameters required for the zero-knowledge
/// proofs used in subsequent CGGMP21 signing and DKG operations.
///
/// # Arguments
///
/// * `eid` - A unique execution ID for this specific protocol run.
/// * `i` - The 1-based index of the local party in the MPC cluster.
/// * `n` - The total number of parties in the MPC cluster.
/// * `party` - The communication channel (`MpcParty`) for exchanging messages.
///
/// # Returns
///
/// The generated `AuxInfo` struct, which can be cached and reused for multiple DKG sessions.
///
/// # Errors
///
/// Returns `MpcError::Internal` if the background thread for prime generation panics.
/// Returns `MpcError::TssProtocol` if the cryptographic protocol fails or message delivery fails.
///
/// # Note
///
/// Prime generation is offloaded to a blocking thread pool (`spawn_blocking`) to prevent
/// starving the Tokio async runtime, as this operation can take several seconds.
pub async fn run_aux_info_gen<Del>(
    eid: ExecutionId<'_>,
    i: u16,
    n: u16,
    party: MpcParty<Cggmp21AuxMsg, Del>,
) -> MpcResult<AuxInfo>
where
    Del: cggmp21::round_based::Delivery<Cggmp21AuxMsg>,
{
    let pregenerated = tokio::task::spawn_blocking(|| {
        PregeneratedPrimes::generate(&mut OsRng)
    })
    .await
    .map_err(|e| mpc_common::error::MpcError::Internal(format!("spawn_blocking failed: {}", e)))?;
    
    let aux = aux_info_gen(eid, i, n, pregenerated)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| mpc_common::error::MpcError::TssProtocol(format!(
            "aux info gen failed: {e}"
        )))?;
        
    Ok(aux)
}

/// Runs the CGGMP21 Distributed Key Generation (DKG) protocol for secp256k1.
///
/// This function orchestrates the multi-round protocol where nodes collaboratively
/// generate a shared master public key and individual secret shares, such that no
/// single node ever knows the complete private key.
///
/// # Arguments
///
/// * `eid` - A unique execution ID for this specific protocol run.
/// * `i` - The 1-based index of the local party.
/// * `n` - The total number of parties.
/// * `t` - The threshold (minimum number of parties required to sign).
/// * `party` - The communication channel for exchanging messages.
/// * `existing_aux` - The pre-generated auxiliary information (from `run_aux_info_gen`).
///
/// # Returns
///
/// The final `KeyShare` containing the local secret share and the shared public key.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if the DKG protocol fails, or if combining the
/// incomplete key share with the auxiliary information fails.
pub async fn run_dkg<Del>(
    eid: ExecutionId<'_>,
    i: u16,
    n: u16,
    t: u16,
    party: MpcParty<Cggmp21KeygenMsg, Del>,
    existing_aux: AuxInfo, 
) -> MpcResult<Cggmp21KeyShare>
where
    Del: cggmp21::round_based::Delivery<Cggmp21KeygenMsg>,
{
    let incomplete = keygen::<Secp256k1>(eid, i, n)
        .set_threshold(t)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| mpc_common::error::MpcError::TssProtocol(format!("keygen failed: {e}")))?;

    let key_share = Cggmp21KeyShare::from_parts((incomplete, existing_aux)).map_err(|e| {
        mpc_common::error::MpcError::TssProtocol(format!("failed to combine key share: {e}"))
    })?;

    Ok(key_share)
}

/// Converts a library-specific `cggmp21::KeyShare` into the generic `mpc_common::types::KeyShare`.
///
/// This function bridges the gap between the cryptographic library's internal representation
/// and the MPC-RS system's unified data model, preparing the share for HSM encryption and storage.
///
/// # Arguments
///
/// * `share` - The `cggmp21::KeyShare` generated by `run_dkg`.
/// * `party_id` - The unique identifier of the local node.
/// * `hsm_id` - The identifier of the HSM that will be used to encrypt this share.
///
/// # Returns
///
/// A generic `mpc_common::types::KeyShare` ready for serialization and HSM wrapping.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if the public key cannot be parsed.
/// Returns `MpcError::Internal` if JSON serialization of the share payload fails.
///
/// # Note
///
/// The internal `cggmp21` payload is serialized using `serde_json` rather than `bincode`.
/// This is a deliberate workaround to bypass `bincode`'s limitation with `deserialize_any`,
/// which is required by some nested structures in the `cggmp21` crate.
pub fn convert_key_share(
    share: &Cggmp21KeyShare, 
    party_id: PartyId,
    hsm_id: HsmIdentifier,
) -> mpc_common::error::MpcResult<mpc_common::types::KeyShare> {
    let pk_bytes = share.shared_public_key().to_bytes(true);

    let public_key = PublicKey::Secp256k1(
        k256::PublicKey::from_sec1_bytes(&pk_bytes)
            .map_err(|e| mpc_common::error::MpcError::TssProtocol(e.to_string()))?,
    );

    // Use serde_json for the internal cggmp21 payload to bypass bincode's deserialize_any limitation
    let share_bytes = serde_json::to_vec(share)
        .map_err(|e| mpc_common::error::MpcError::Internal(format!("serde_json serialize failed: {}", e)))?;

    Ok(mpc_common::types::KeyShare {
        party_id,
        public_key,
        encrypted_share: EncryptedShare {
            ciphertext: share_bytes,
            hsm_id,
        },
        metadata: ShareMetadata {
            curve: Curve::Secp256k1,
            protocol_version: "cggmp21-0.6".into(),
            created_at: chrono::Utc::now(),
            party_id,
        },
    })
}

