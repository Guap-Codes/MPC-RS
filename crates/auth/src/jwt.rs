//! # JWT Manager Module
//!
//! This module provides a robust, stateful manager for creating and validating
//! JSON Web Tokens (JWTs) within the MPC-RS ecosystem.
//!
//! ## Security Context
//! MPC-RS relies on **Scope-Bound JWT Authentication** to prevent cross-service
//! token replay attacks. The [`JwtManager`] enforces strict validation rules by default,
//! ensuring that tokens are cryptographically verified, unexpired, and targeted
//! at the correct audience (e.g., `mpc-api` vs `mpc-coordinator`).

use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use crate::claims::Claims;

/// Errors that can occur during JWT encoding, decoding, or configuration.
///
/// This enum wraps the underlying `jsonwebtoken` errors and adds domain-specific
/// variants for missing keys or unsupported algorithms, allowing the API gateway
/// to map them to appropriate HTTP status codes (e.g., 401 Unauthorized or 500 Internal Server Error).
#[derive(thiserror::Error, Debug)]
pub enum JwtError {
    /// An error originating from the underlying `jsonwebtoken` crate 
    /// (e.g., invalid signature, malformed token, expired token).
    #[error("JWT encode/decode error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// The requested cryptographic algorithm is not supported by this manager.
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    
    /// Attempted to sign a token, but the manager was instantiated without a private key.
    #[error("Missing encoding key")]
    MissingEncodingKey,
}

/// A stateful manager for creating and validating JSON Web Tokens (JWTs).
///
/// The `JwtManager` holds the cryptographic keys (encoding/decoding) and the
/// strict validation rules (issuer, audience, expiration) required by the MPC-RS
/// security model. It is designed to be instantiated once at application startup
/// and shared across the application (e.g., via `Arc<JwtManager>`).
///
/// # Default Behavior
/// By default, a newly constructed `JwtManager` strictly enforces:
/// - **Expiration (`exp`)**: Tokens must not be expired.
/// - **Issuer (`iss`)**: Tokens must be issued by `"mpc-rs"`.
/// - **Audience (`aud`)**: Tokens must be intended for `"mpc-api"`.
///
/// These defaults can be overridden using the provided builder methods.
pub struct JwtManager {
    algorithm: Algorithm,
    encoding_key: Option<EncodingKey>,
    decoding_key: DecodingKey,
    expected_iss: Option<String>,
    expected_aud: Option<String>,
}

impl JwtManager {
    /// Creates a new `JwtManager` with the specified algorithm and keys.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The cryptographic algorithm to use (e.g., `Algorithm::RS256` or `Algorithm::HS256`).
    /// * `public_key_pem` - The PEM-encoded public key (for asymmetric algorithms like RSA) or the shared secret (for HMAC).
    /// * `private_key_pem` - An optional PEM-encoded private key. Required if this manager instance will be used to *create* (sign) tokens.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtError`] if:
    /// - The provided algorithm is not supported.
    /// - The PEM keys are malformed or cannot be parsed by the underlying `jsonwebtoken` crate.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use mpc_auth::jwt::{JwtManager, JwtError};
    /// use jsonwebtoken::Algorithm;
    ///
    /// # fn main() -> Result<(), JwtError> {
    /// let public_pem = include_bytes!("../../../config/public.pem");
    /// let private_pem = include_bytes!("../../../config/private.pem");
    ///
    /// // Create a manager capable of both signing and validating
    /// let manager = JwtManager::new(Algorithm::RS256, public_pem, Some(private_pem))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        algorithm: Algorithm,
        public_key_pem: &[u8],
        private_key_pem: Option<&[u8]>,
    ) -> Result<Self, JwtError> {
        let decoding_key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                DecodingKey::from_secret(public_key_pem)
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
            | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                DecodingKey::from_rsa_pem(public_key_pem)?
            }
            _ => return Err(JwtError::UnsupportedAlgorithm),
        };

        let encoding_key = if let Some(priv_pem) = private_key_pem {
            let key = match algorithm {
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                    EncodingKey::from_secret(priv_pem)
                }
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
                | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                    EncodingKey::from_rsa_pem(priv_pem)?
                }
                _ => return Err(JwtError::UnsupportedAlgorithm),
            };
            Some(key)
        } else {
            None
        };

        Ok(Self {
            algorithm,
            encoding_key,
            decoding_key,
            // Defaults matching the constants in crates/auth/src/claims.rs
            expected_iss: Some("mpc-rs".to_string()),
            expected_aud: Some("mpc-api".to_string()),
        })
    }

    /// Overrides the expected issuer (`iss` claim) for validation.
    ///
    /// By default, the manager expects `"mpc-rs"`. Use this to validate tokens
    /// from external identity providers or different internal services.
    #[must_use]
    pub fn with_issuer(mut self, iss: impl Into<String>) -> Self {
        self.expected_iss = Some(iss.into());
        self
    }

    /// Overrides the expected audience (`aud` claim) for validation.
    ///
    /// By default, the manager expects `"mpc-api"`. Use this when configuring
    /// the `mpc-coordinator` to strictly require `aud: "mpc-coordinator"`.
    #[must_use]
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.expected_aud = Some(aud.into());
        self
    }

    /// Disables issuer (`iss`) validation.
    /// 
    /// # Warning
    /// This is generally discouraged in production. Only use this for testing 
    /// or for completely open, unauthenticated endpoints.
    #[must_use]
    pub fn without_issuer_validation(mut self) -> Self {
        self.expected_iss = None;
        self
    }

    /// Disables audience (`aud`) validation.
    /// 
    /// # Warning
    /// Disabling audience validation removes the primary defense against 
    /// cross-service token replay attacks in the MPC-RS architecture.
    #[must_use]
    pub fn without_audience_validation(mut self) -> Self {
        self.expected_aud = None;
        self
    }

    /// Signs a set of claims and produces a compact JWT string.
    ///
    /// # Arguments
    ///
    /// * `claims` - The [`Claims`] payload to sign.
    ///
    /// # Returns
    ///
    /// A `String` containing the base64url-encoded JWT (header.payload.signature).
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::MissingEncodingKey`] if the manager was instantiated without a private key.
    /// Returns [`JwtError::Jwt`] if the underlying signing operation fails.
    pub fn create_token(&self, claims: &Claims) -> Result<String, JwtError> {
        let header = Header::new(self.algorithm);
        let key = self
            .encoding_key
            .as_ref()
            .ok_or(JwtError::MissingEncodingKey)?;
        Ok(encode(&header, claims, key)?)
    }

    /// Validates a JWT string and extracts the verified claims.
    ///
    /// This method enforces strict security checks based on the manager's configuration:
    /// 1. **Cryptographic Signature**: Verifies the signature against the stored decoding key.
    /// 2. **Expiration (`exp`)**: Strictly required and validated against the current system time.
    /// 3. **Issuer (`iss`)**: If configured, strictly required and matched against the expected issuer.
    /// 4. **Audience (`aud`)**: If configured, strictly required and matched against the expected audience.
    ///
    /// # Arguments
    ///
    /// * `token` - The compact JWT string to validate.
    ///
    /// # Returns
    ///
    /// The decoded and verified [`Claims`] struct.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtError`] if the token is malformed, the signature is invalid,
    /// the token is expired, or required claims (`exp`, `iss`, `aud`) are missing/mismatched.
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(self.algorithm);
        
        // 1. Expiration is strictly required
        validation.validate_exp = true;
        validation.required_spec_claims.insert("exp".to_string());

        // 2. Issuer validation
        if let Some(iss) = &self.expected_iss {
            validation.set_issuer(&[iss]);
            // Force the token to actually contain the `iss` claim
            validation.required_spec_claims.insert("iss".to_string());
        }

        // 3. Audience validation
        if let Some(aud) = &self.expected_aud {
            validation.set_audience(&[aud]);
            // Force the token to actually contain the `aud` claim
            validation.required_spec_claims.insert("aud".to_string());
        }

        let data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }
}
