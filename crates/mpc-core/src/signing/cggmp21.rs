//! # CGGMP21 Threshold Signing
//!
//! This module implements the threshold signing phase of the CGGMP21 protocol
//! for the secp256k1 curve. It allows a subset of parties (meeting the threshold)
//! to collaboratively sign a message digest without ever reconstructing the full
//! private key on any single node.
//!
//! ## Hierarchical Deterministic (HD) Derivation
//! The protocol supports on-the-fly HD derivation (BIP32/SLIP-0010). By providing
//! a derivation path (e.g., `"m/44'/60'/0'/0/0"`), the nodes can collaboratively
//! derive the child key and sign with it, using the master key share generated
//! during the DKG phase as the root.

use cggmp21::{
    signing,
    supported_curves::Secp256k1,
    DataToSign, ExecutionId, KeyShare, Signature, Presignature,
    signing::msg::Msg,
    round_based::MpcParty,
};
use mpc_common::{
    error::{MpcError, MpcResult},
    types::SignResult,
};

// --- TYPE ALIASES FOR READABILITY ---
// Explicitly bind the types to the Secp256k1 curve and Sha256 digest.
type SigningMsg = Msg<Secp256k1, sha2::Sha256>;
type SigningKeyShare = KeyShare<Secp256k1>;
type SigningDataToSign = DataToSign<Secp256k1>;
type SigningSignature = Signature<Secp256k1>;
type SigningPresignature = Presignature<Secp256k1>;
// ------------------------------------

/// Executes the full CGGMP21 threshold signing protocol.
///
/// This function orchestrates the multi-round signing process, optionally
/// incorporating a BIP32 derivation path to sign with a child key rather than
/// the master key.
///
/// # Arguments
///
/// * `eid` - A unique execution ID for this specific protocol run.
/// * `i` - The 1-based index of the local party.
/// * `parties_at_keygen` - A slice of the 1-based indices of all parties that
///   participated in the original DKG for this key.
/// * `key_share` - The local party's secret key share (and aux info).
/// * `data_to_sign` - The 32-byte message digest to be signed.
/// * `derivation_path` - An optional BIP32 derivation path (e.g., `"m/44'/60'/0'/0/0"`).
///   If `None`, the master key is used.
/// * `party` - The communication channel for exchanging signing messages.
///
/// # Returns
///
/// The final aggregated `Signature` upon successful completion of the protocol.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if the derivation path is invalid, or if the
/// cryptographic signing protocol fails (e.g., due to malicious behavior or network drops).
pub async fn run_signing<Del>(
    eid: ExecutionId<'_>,
    i: u16,
    parties_at_keygen: &[u16],
    key_share: &SigningKeyShare,
    data_to_sign: SigningDataToSign,
    derivation_path: Option<&str>,       // e.g. "m/44'/60'/0'/0/0"
    party: MpcParty<SigningMsg, Del>,
) -> MpcResult<SigningSignature>
where
    // Bound the delivery type to ensure it can transport our specific signing message type.
    Del: cggmp21::round_based::Delivery<SigningMsg>,
{
    let builder = signing(eid, i, parties_at_keygen, key_share);
    
    // Parse the &str into a Vec<u32> before passing it to the builder
    let builder = if let Some(path_str) = derivation_path {
        let path_indices = parse_derivation_path(path_str)?;
        builder.set_derivation_path(path_indices).map_err(|e| {
            MpcError::TssProtocol(format!("invalid derivation path: {e}"))
        })?
    } else {
        builder
    };
    builder
        .sign(&mut rand::rngs::OsRng, party, data_to_sign)
        .await
        .map_err(|e| MpcError::TssProtocol(format!("signing failed: {:?}", e)))
}

/// Generates a presignature for the CGGMP21 protocol.
///
/// Presignatures are an optimization technique in CGGMP21. They allow nodes to
/// perform the most computationally expensive parts of the signing protocol
/// (generating nonces and zero-knowledge proofs) *before* the actual message
/// to be signed is known. This significantly reduces the latency of the final
/// signing phase.
///
/// # Arguments
///
/// * `eid` - A unique execution ID for this specific protocol run.
/// * `i` - The 1-based index of the local party.
/// * `parties_at_keygen` - A slice of the 1-based indices of all parties that
///   participated in the original DKG for this key.
/// * `key_share` - The local party's secret key share (and aux info).
/// * `derivation_path` - An optional BIP32 derivation path.
/// * `party` - The communication channel for exchanging presignature messages.
///
/// # Returns
///
/// A `Presignature` object that can be cached and later used in `sign_with_presignature`.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if the derivation path is invalid, or if the
/// presignature generation protocol fails.
pub async fn generate_presignature<Del>(
    eid: ExecutionId<'_>,
    i: u16,
    parties_at_keygen: &[u16],
    key_share: &SigningKeyShare,
    derivation_path: Option<&str>,
    party: MpcParty<SigningMsg, Del>,
) -> MpcResult<SigningPresignature>
where
    Del: cggmp21::round_based::Delivery<SigningMsg>,
{
    let builder = signing(eid, i, parties_at_keygen, key_share);

    // Parse the &str into a Vec<u32> before passing it to the builder
    let builder = if let Some(path_str) = derivation_path {
        let path_indices = parse_derivation_path(path_str)?;
        builder.set_derivation_path(path_indices).map_err(|e| {
            MpcError::TssProtocol(format!("invalid derivation path: {e}"))
        })?
    } else {
        builder
    };
    builder
        .generate_presignature(&mut rand::rngs::OsRng, party)
        .await
        .map_err(|e| MpcError::TssProtocol(format!("presignature generation failed: {e}")))
}

/// Converts a library-specific `cggmp21::Signature` into the generic `mpc_common::types::SignResult`.
///
/// This function bridges the gap between the cryptographic library's internal
/// representation and the MPC-RS system's unified data model, preparing the
/// signature for aggregation and return to the API Gateway.
///
/// # Arguments
///
/// * `sig` - The `cggmp21::Signature` generated by the signing protocol.
/// * `session_id` - The unique identifier of the signing session.
///
/// # Returns
///
/// A `SignResult` containing the session ID, the serialized signature bytes,
/// and the current UTC timestamp.
pub fn convert_signature(sig: &SigningSignature, session_id: mpc_common::types::SessionId) -> SignResult {
    // `serialized_len` is an associated function, so we call it on the type `SigningSignature`
    // rather than the instance `sig`.
    let mut buf = vec![0u8; SigningSignature::serialized_len()];

    // `write_to_slice` takes `&self`, so calling it on the instance is correct.
    sig.write_to_slice(&mut buf);

    SignResult {
        session_id,
        signature: buf,
        committed_at: chrono::Utc::now(),
    }
}

/// Parses a BIP32 derivation path string into a vector of `u32` indices.
///
/// # Arguments
///
/// * `path` - The derivation path string (e.g., `"m/44'/60'/0'/0/0"`).
///
/// # Returns
///
/// A `Vec<u32>` representing the path indices.
///
/// # Errors
///
/// Returns `MpcError::TssProtocol` if any segment of the path cannot be parsed
/// as a valid `u32`.
///
/// # Note
///
/// This helper strips hardened indicators (`'` or `h`) from the string. However,
/// it is important to note that standard CGGMP21 threshold signing typically
/// only supports *non-hardened* derivation paths, as hardened derivation requires
/// the parent private key, which is never reconstructed in an MPC setting.
fn parse_derivation_path(path: &str) -> Result<Vec<u32>, MpcError> {
    let path = path.strip_prefix("m/").unwrap_or(path);
    path.split('/')
        .map(|part| {
            // Strip hardened indicators (') or (h) if they exist in the string.
            // Note: cggmp21 threshold signing typically only supports non-hardened derivation.
            let clean_part = part.trim_end_matches('\'').trim_end_matches('h');
            clean_part.parse::<u32>().map_err(|e| {
                MpcError::TssProtocol(format!("invalid path index '{part}': {e}"))
            })
        })
        .collect()
}
