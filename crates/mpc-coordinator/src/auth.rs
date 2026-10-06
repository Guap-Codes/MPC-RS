//! # gRPC Authentication Middleware
//!
//! This module provides the authentication logic for the Coordinator's external-facing 
//! gRPC service. It extracts, validates, and authorizes JWTs attached to incoming requests.

use auth::{Claims, JwtManager};
use tonic::{Request, Status};

/// Extracts and validates JWT claims from a gRPC request's metadata.
///
/// # Arguments
///
/// * `req` - The incoming tonic `Request`.
/// * `jwt_manager` - The shared `JwtManager` instance used to validate the token's 
///   signature, expiration, issuer, and audience.
///
/// # Returns
///
/// The validated `Claims` payload if the token is valid and the user has sufficient permissions.
///
/// # Errors
///
/// Returns `Status::unauthenticated` if:
/// - The `authorization` header is missing or malformed.
/// - The token is expired, has an invalid signature, or fails audience/issuer checks.
///
/// Returns `Status::permission_denied` if:
/// - The validated claims do not contain either the `"signer"` or `"admin"` role.
pub fn authenticate<T>(req: &Request<T>, jwt_manager: &JwtManager) -> Result<Claims, Status> {
    let token = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("missing token"))?;

    let claims = jwt_manager
        .validate_token(token)
        .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))?;

    // Enforce Role-Based Access Control (RBAC)
    if !claims.has_role("signer") && !claims.has_role("admin") {
        return Err(Status::permission_denied("insufficient role"));
    }
    
    Ok(claims)
}




