//! # JWT Claims Module
//!
//! This module defines the custom JSON Web Token (JWT) claims structure used 
//! throughout the MPC-RS ecosystem for authentication and authorization.
//!
//! ## Security Context
//! MPC-RS enforces strict **Scope-Bound JWT Authentication**. Tokens are minted 
//! with specific audiences (e.g., `mpc-api` for external requests, `mpc-coordinator` 
//! for internal admin operations) and Role-Based Access Control (RBAC) roles to 
//! prevent cross-service token replay attacks and enforce the principle of least privilege.

use serde::{Deserialize, Serialize};

/// Standard JWT claims extended with custom Role-Based Access Control (RBAC) roles.
///
/// This struct represents the payload of a JWT. It includes standard registered 
/// claims defined by RFC 7519 (such as `sub`, `exp`, `iat`, `iss`, and `aud`) 
/// alongside a custom `roles` array used by the MPC-RS policy engine.
///
/// # Security Note
/// The `aud` (audience) field is critical in MPC-RS. A token minted for 
/// `aud: "mpc-api"` must be cryptographically rejected if presented to the 
/// `mpc-coordinator` administrative endpoints.
///
/// # Example
/// ```rust
/// use mpc_auth::claims::Claims;
///
/// let claims = Claims::new("user_123", vec!["admin".to_string()], 3600);
/// assert!(claims.has_role("admin"));
/// assert!(!claims.has_role("auditor"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// **Subject (`sub`)**: The unique identifier of the entity (user, service, or client) 
    /// that this token represents.
    pub sub: String,

    /// **Expiration Time (`exp`)**: The exact UTC timestamp (in seconds since epoch) 
    /// after which this token MUST be rejected by the middleware.
    pub exp: usize,
    
    /// **Issued At (`iat`)**: The UTC timestamp (in seconds since epoch) when this 
    /// token was originally minted. Useful for auditing and token revocation checks.
    pub iat: usize,
    
    /// **Issuer (`iss`)**: The entity that issued the token.
    pub iss: Option<String>,
    
    /// **Audience (`aud`)**: The intended recipient of the token. 
    /// Valid values in MPC-RS include `"mpc-api"` (for transaction requests) 
    /// and `"mpc-coordinator"` (for administrative DKG/signing operations).
    pub aud: Option<String>,
    
    /// **Roles**: A custom list of RBAC roles granted to the subject. 
    /// Common roles include `"admin"`, `"signer"`, `"auditor"`, and `"readonly"`.
    pub roles: Vec<String>,
}

impl Claims {
    /// Mints a new set of claims with a given subject, roles, and time-to-live (TTL).
    ///
    /// Automatically sets the `iat` (Issued At) to the current UTC time and calculates 
    /// the `exp` (Expiration) based on the provided `ttl_secs`. The `iss` is hardcoded 
    /// to `"mpc-rs"` and the default `aud` is set to `"mpc-api"`.
    ///
    /// # Arguments
    ///
    /// * `subject` - A string slice representing the unique identifier of the token bearer.
    /// * `roles` - A vector of strings representing the RBAC roles assigned to this token.
    /// * `ttl_secs` - The validity duration of the token in seconds (e.g., `3600` for 1 hour).
    ///
    /// # Returns
    ///
    /// A fully populated [`Claims`] instance ready to be signed into a JWT.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mpc_auth::claims::Claims;
    ///
    /// // Mint a token for an admin valid for 24 hours
    /// let claims = Claims::new("ops_team", vec!["admin".to_string()], 86400);
    /// assert_eq!(claims.sub, "ops_team");
    /// assert!(claims.has_role("admin"));
    /// ```
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::as_conversions
    )]
    pub fn new(subject: &str, roles: Vec<String>, ttl_secs: u64) -> Self {
        // Convert to u64 first to handle the sign safely, then use saturating_add 
        // to prevent arithmetic_side_effects before the final usize cast.
        let now = chrono::Utc::now().timestamp() as u64;
        let exp = now.saturating_add(ttl_secs) as usize;
        let iat = now as usize;

        Self {
            sub: subject.to_string(),
            exp,
            iat,
            iss: Some("mpc-rs".into()),
            aud: Some("mpc-api".into()),
            roles,
        }
    }

    /// Checks whether the token bearer possesses a specific RBAC role.
    ///
    /// Performs a case-sensitive exact match against the `roles` array.
    ///
    /// # Arguments
    ///
    /// * `role` - A string slice representing the role to check for (e.g., `"admin"`).
    ///
    /// # Returns
    ///
    /// `true` if the role is present in the claims, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use mpc_auth::claims::Claims;
    /// let claims = Claims::new("user_1", vec!["signer".to_string()], 3600);
    /// assert!(claims.has_role("signer"));
    /// assert!(!claims.has_role("admin"));
    /// ```
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Checks whether the token bearer possesses at least one of the provided RBAC roles.
    ///
    /// This is highly useful for route guards where multiple roles might grant access 
    /// to the same endpoint (e.g., an endpoint accessible by both `"admin"` and `"auditor"`).
    ///
    /// # Arguments
    ///
    /// * `roles` - A slice of string slices representing the acceptable roles.
    ///
    /// # Returns
    ///
    /// `true` if the bearer has *any* of the specified roles, `false` if they have none.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use mpc_auth::claims::Claims;
    /// let claims = Claims::new("user_1", vec!["auditor".to_string()], 3600);
    /// 
    /// // Access granted if user is admin OR auditor
    /// assert!(claims.has_any_role(&["admin", "auditor"]));
    /// 
    /// // Access denied if checking for roles the user doesn't have
    /// assert!(!claims.has_any_role(&["admin", "superuser"]));
    /// ```
    #[must_use]
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }
}

