//! # Elliptic Curve Abstractions
//!
//! This module provides a unified abstraction over the elliptic curves used in the MPC-RS system.
//! By defining the `CurveOps` trait and associated enums (`CurvePoint`, `Scalar`), the core
//! cryptographic protocol logic can remain generic over the specific curve choice.
//!
//! ## Supported Curves
//! - **secp256k1**: Used for Bitcoin, Ethereum, and Tron (via CGGMP21 ECDSA).
//! - **Ed25519**: Used for Solana (via FROST Schnorr signatures).
//! - **Curve25519**: Used for X25519 key exchange and auxiliary cryptographic operations.
//!
//! ## Security Note
//! All scalar types implement the `Zeroize` trait to ensure that sensitive cryptographic material
//! is securely wiped from memory when the variable goes out of scope, preventing leakage via core dumps.

use zeroize::Zeroize;

mod secp256k1;
mod ed25519;
mod curve25519;

pub use secp256k1::Secp256k1Curve;
pub use ed25519::Ed25519Curve;
pub use curve25519::Curve25519Curve;

/// A point on a supported elliptic curve.
///
/// This enum acts as a type-erased wrapper around the specific point types
/// provided by the underlying cryptographic libraries (`k256` and `curve25519-dalek`),
/// allowing the MPC protocol to handle multiple curves uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurvePoint {
    /// A point on the secp256k1 curve (used for ECDSA).
    Secp256k1(k256::ProjectivePoint),
    /// A point on the Ed25519 curve (used for Schnorr signatures).
    Ed25519(curve25519_dalek::EdwardsPoint),
    /// A point on the Curve25519 curve (used for X25519 key exchange).
    Curve25519(curve25519_dalek::EdwardsPoint),
}

/// A scalar value used for elliptic curve point multiplication.
///
/// This enum wraps the specific scalar types from the underlying libraries.
/// It implements `Zeroize` to ensure secure memory cleanup of secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub enum Scalar {
    /// A scalar modulo the secp256k1 curve order.
    Secp256k1(k256::Scalar),
    /// A scalar modulo the Ed25519 curve order.
    Ed25519(curve25519_dalek::Scalar),
    /// A scalar modulo the Curve25519 curve order.
    Curve25519(curve25519_dalek::Scalar),
}

/// Trait defining the fundamental elliptic curve operations required by the MPC protocol.
///
/// Implementors of this trait provide curve-specific logic for point addition,
/// scalar multiplication, and serialization, allowing the higher-level MPC logic
/// to operate generically without being coupled to a specific cryptographic library.
pub trait CurveOps {
    /// The concrete type representing a point on this curve.
    type Point;
    
    /// The concrete type representing a scalar for this curve.
    /// Must implement `Clone` and `Zeroize` for secure handling of secret material.
    type Scalar: Clone + Zeroize;

    /// Returns the canonical base point (generator) for this curve.
    ///
    /// # Returns
    ///
    /// The generator point `G` used for public key derivation.
    fn base_point() -> Self::Point;

    /// Adds two points on the curve.
    ///
    /// # Arguments
    ///
    /// * `a` - The first point.
    /// * `b` - The second point.
    ///
    /// # Returns
    ///
    /// The resulting point `a + b`.
    fn add(a: &Self::Point, b: &Self::Point) -> Self::Point;

    /// Multiplies a point by a scalar.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to be multiplied.
    /// * `scalar` - The scalar multiplier.
    ///
    /// # Returns
    ///
    /// The resulting point `scalar * point`.
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point;

    /// Attempts to parse a scalar from a raw byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the scalar.
    ///
    /// # Returns
    ///
    /// `Some(Scalar)` if the bytes represent a valid scalar for this curve,
    /// or `None` if the length is incorrect or the value is invalid (e.g., out of bounds).
    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar>;

    /// Serializes a curve point into a raw byte vector.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to serialize.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the serialized point (e.g., compressed or uncompressed format,
    /// depending on the curve's standard).
    fn point_to_bytes(point: &Self::Point) -> Vec<u8>;
}

