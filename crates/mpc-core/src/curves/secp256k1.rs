//! # secp256k1 Curve Implementation
//!
//! This module provides the `CurveOps` implementation for the secp256k1 elliptic curve,
//! which is the standard curve used for Bitcoin, Ethereum, and Tron in the MPC-RS system.

use super::*;
use k256::elliptic_curve::{Group, sec1::ToEncodedPoint, ops::Reduce};
use k256::U256;

/// The secp256k1 elliptic curve implementation.
///
/// This struct serves as a type-level marker to implement the [`CurveOps`] trait
/// for the secp256k1 curve, providing curve-specific operations like point addition,
/// scalar multiplication, and serialization.
pub struct Secp256k1Curve;

impl CurveOps for Secp256k1Curve {
    type Point = k256::ProjectivePoint;
    type Scalar = k256::Scalar;

    /// Returns the canonical generator point G for the secp256k1 curve.
    fn base_point() -> Self::Point {
        k256::ProjectivePoint::GENERATOR
    }

    /// Adds two points on the secp256k1 curve.
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

    /// Multiplies a point on the secp256k1 curve by a scalar.
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
        point * scalar
    }

    /// Converts a byte slice into a secp256k1 scalar.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the scalar. It must be exactly 32 bytes long.
    ///
    /// # Returns
    ///
    /// * `Some(Scalar)` if the conversion is successful. The bytes are reduced modulo
    ///   the curve order to ensure they represent a valid scalar, even if the input
    ///   value is greater than or equal to the curve order.
    /// * `None` if the input slice is not exactly 32 bytes long.
    ///
    /// # Note
    ///
    /// Clippy may incorrectly flag the `try_into` as an "unnecessary fallible conversion"
    /// due to complex type-level integer resolution in the `generic-array` crate.
    /// However, this is the correct and safe way to perform this conversion without
    /// risking a panic on malformed input.
    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
        #[allow(clippy::unnecessary_fallible_conversions)]
        let field_bytes: &k256::FieldBytes = bytes.try_into().ok()?;
        
        Some(<k256::Scalar as Reduce<U256>>::reduce_bytes(field_bytes))
    }

    /// Serializes a secp256k1 point into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `point` - The point to serialize.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the point serialized in uncompressed SEC1 format
    /// (`0x04 || x || y`). This format is commonly required by blockchain protocols
    /// like Ethereum and Tron for address derivation and transaction building.
    fn point_to_bytes(point: &Self::Point) -> Vec<u8> {
        point.to_affine().to_encoded_point(false).as_bytes().to_vec()
    }
}

