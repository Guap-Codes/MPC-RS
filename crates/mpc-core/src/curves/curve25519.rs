//! # Curve25519 Implementation
//!
//! This module provides the `CurveOps` implementation for the Curve25519 elliptic curve,
//! primarily used for X25519 key exchange and auxiliary cryptographic operations in MPC-RS.
//! It leverages the `curve25519-dalek` crate for constant-time, side-channel resistant operations.

use super::*;
use curve25519_dalek::Scalar;
use curve25519_dalek::EdwardsPoint;

/// The Curve25519 elliptic curve implementation.
///
/// This struct serves as a type-level marker to implement the [`CurveOps`] trait
/// for the Curve25519 curve (using its birationally equivalent Edwards curve representation).
pub struct Curve25519Curve;

impl CurveOps for Curve25519Curve {
    type Point = EdwardsPoint;
    type Scalar = Scalar;

    /// Returns the canonical generator point (base point) for the Curve25519 Edwards curve.
    ///
    /// # Returns
    ///
    /// The standard base point `B` used for all Curve25519 scalar multiplications.
    fn base_point() -> Self::Point {
        curve25519_dalek::constants::ED25519_BASEPOINT_POINT
    }

    /// Adds two points on the Curve25519 Edwards curve.
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

    /// Multiplies a point on the Curve25519 curve by a scalar.
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

    /// Converts a byte slice into a Curve25519 scalar.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the scalar. It must be exactly 32 bytes long.
    ///
    /// # Returns
    ///
    /// * `Some(Scalar)` if the conversion is successful and the bytes represent a valid, 
    ///   canonical scalar (i.e., strictly less than the group order).
    /// * `None` if the input slice is not exactly 32 bytes long or if the value is non-canonical.
    ///
    /// # Note
    ///
    /// Curve25519 scalars are strictly validated to be in canonical form. This prevents 
    /// malleability issues and signature forgery attacks that can arise from non-canonical 
    /// scalar representations (e.g., values >= the group order).
    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
        Scalar::from_canonical_bytes(bytes.try_into().ok()?).into()
    }

    /// Serializes a Curve25519 point into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to serialize.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the point serialized in the compressed Edwards y-coordinate 
    /// format (exactly 32 bytes). This is the standard wire format for Curve25519 public keys.
    fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
        point.compress().to_bytes().to_vec()
    }
}

