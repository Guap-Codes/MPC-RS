//! # Ed25519 Curve Implementation
//!
//! This module provides the `CurveOps` implementation for the Ed25519 elliptic curve,
//! which is the standard curve used for Solana in the MPC-RS system (via the FROST protocol).
//! It leverages the `curve25519-dalek` crate for constant-time, side-channel resistant operations.

use super::*;
use curve25519_dalek::{Scalar, EdwardsPoint, constants};

/// The Ed25519 elliptic curve implementation.
///
/// This struct serves as a type-level marker to implement the [`CurveOps`] trait
/// for the Ed25519 curve, enabling threshold Schnorr signing via the FROST protocol.
pub struct Ed25519Curve;

impl CurveOps for Ed25519Curve {
    type Point = EdwardsPoint;
    type Scalar = Scalar;

    /// Returns the canonical generator point (base point) for the Ed25519 curve.
    ///
    /// # Returns
    ///
    /// The standard base point `B` used for all Ed25519 scalar multiplications.
    ///
    /// # Note
    ///
    /// Using the constant directly from `curve25519_dalek::constants` avoids potential 
    /// version conflicts or trait resolution issues that can occur when relying on the 
    /// generic `group` crate's `Group::generator()` method.
    fn base_point() -> Self::Point {
        constants::ED25519_BASEPOINT_POINT
    }

    /// Adds two points on the Ed25519 Edwards curve.
    ///
    /// # Arguments
    ///
    /// * `a` - The first point.
    /// * `b` - The second point.
    ///
    /// # Returns
    ///
    /// The resulting point `a + b` on the curve.
    fn add(a: &Self::Point, b: &Self::Point) -> Self::Point {
        a + b
    }

    /// Multiplies a point on the Ed25519 curve by a scalar.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to be multiplied.
    /// * `scalar` - The scalar multiplier.
    ///
    /// # Returns
    ///
    /// The resulting point `scalar * point` on the curve.
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        scalar * point
    }

    /// Converts a byte slice into an Ed25519 scalar.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the scalar. It must be exactly 32 bytes long.
    ///
    /// # Returns
    ///
    /// * `Some(Scalar)` if the conversion is successful. The input bytes are reduced 
    ///   modulo the group order `l`.
    /// * `None` if the input slice is not exactly 32 bytes long.
    ///
    /// # Note
    ///
    /// Unlike strict canonical validation, Ed25519 scalars are typically reduced modulo 
    /// the group order `l`. This behavior matches the expectations of the FROST protocol 
    /// and standard Ed25519 implementations, which handle modular reduction internally 
    /// to ensure the scalar falls within the valid range `[0, l-1]`.
    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
        Some(Scalar::from_bytes_mod_order(bytes.try_into().ok()?))
    }

    /// Serializes an Ed25519 point into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to serialize.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the point serialized in the compressed Edwards y-coordinate 
    /// format (exactly 32 bytes). This is the standard wire format for Ed25519 public keys 
    /// and FROST verification shares.
    fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
        point.compress().to_bytes().to_vec()
    }
}
