//! # OAuth2 / OIDC Token Validation
//!
//! This module provides an asynchronous validator for OAuth2 and OpenID Connect (OIDC)
//! access tokens using JSON Web Key Sets (JWKS).
//!
//! ## Feature Flag
//! This module is only compiled when the `oauth` feature is enabled in your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! mpc-auth = { version = "0.1", features = ["oauth"] }
//! ```
//!
//! ## Architecture
//! The [`OAuthValidator`] fetches public keys from an identity provider's JWKS endpoint,
//! caches them in memory using a concurrent [`tokio::sync::RwLock`], and uses them to
//! cryptographically verify incoming JWTs. It strictly enforces issuer and audience claims
//! based on the provided [`OAuthConfig`].

#[cfg(feature = "oauth")]
use jsonwebtoken::{decode, jwk::JwkSet, Algorithm, DecodingKey, Validation};
#[cfg(feature = "oauth")]
use crate::claims::Claims;
#[cfg(feature = "oauth")]
use std::collections::HashMap;

/// Configuration for an OAuth2 / OIDC identity provider.
///
/// This struct holds the necessary metadata to validate tokens issued by a specific provider
/// (e.g., Auth0, Okta, Keycloak, or a custom OIDC server).
#[cfg(feature = "oauth")]
pub struct OAuthConfig {
    /// The expected `iss` (issuer) claim in the JWT. 
    /// Must exactly match the issuer URL provided by the identity provider.
    pub issuer: String,

    /// The expected `aud` (audience) claim. 
    /// If `None`, audience validation is disabled (not recommended for production).
    pub audience: Option<String>,

    /// The URL of the provider's JWKS (JSON Web Key Set) endpoint.
    /// Example: `https://your-domain.auth0.com/.well-known/jwks.json`
    pub jwks_url: String,

    /// The list of allowed cryptographic algorithms for token signatures (e.g., `RS256`, `ES256`).
    /// Restricting this prevents algorithm confusion attacks.
    pub algorithms: Vec<Algorithm>,
}

/// Errors that may occur during OAuth2 token fetching, caching, or validation.
#[cfg(feature = "oauth")]
#[derive(thiserror::Error, Debug)]
pub enum OAuthError {
    /// An error occurred while making the HTTP request to the JWKS endpoint.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// An error occurred during JWT decoding, signature verification, or claims validation.
    /// This includes expired tokens, invalid signatures, and issuer/audience mismatches 
    /// caught by the underlying `jsonwebtoken` crate.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// The `iss` (issuer) claim in the token did not match the expected issuer.
    /// 
    /// *Note: In the current implementation, the underlying `jsonwebtoken` crate handles 
    /// issuer validation and will return an [`OAuthError::Jwt`] instead. This variant 
    /// is provided for future manual validation extensions.*
    #[error("Invalid issuer")]
    InvalidIssuer,

    /// The token's `kid` (Key ID) header is missing, or no matching key was found in the cached JWKS.
    /// If this occurs, it usually indicates that the provider has rotated their keys and 
    /// [`OAuthValidator::refresh_keys`] needs to be called.
    #[error("Invalid or missing key in JWKS")]
    InvalidKey,
}

/// An asynchronous validator that fetches JWKS from an OAuth2 provider and validates tokens.
///
/// The `OAuthValidator` maintains an in-memory cache of the provider's public keys.
/// Because identity providers periodically rotate their keys, it is highly recommended
/// to call [`OAuthValidator::refresh_keys`] periodically (e.g., via a background task)
/// or implement a retry mechanism that refreshes the cache if a token's `kid` is not found.
///
/// # Example
///
/// ```rust,no_run
/// use mpc_auth::oauth::{OAuthConfig, OAuthValidator};
/// use jsonwebtoken::Algorithm;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = OAuthConfig {
///     issuer: "https://your-tenant.auth0.com/".to_string(),
///     audience: Some("https://api.mpc-rs.com".to_string()),
///     jwks_url: "https://your-tenant.auth0.com/.well-known/jwks.json".to_string(),
///     algorithms: vec![Algorithm::RS256],
/// };
///
/// let validator = OAuthValidator::new(config);
///
/// // Fetch and cache the public keys before validating tokens
/// validator.refresh_keys().await?;
///
/// // Validate an incoming bearer token
/// let token = "eyJhbGciOi...";
/// let claims = validator.validate_token(token).await?;
/// println!("Authenticated user: {}", claims.sub);
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "oauth")]
pub struct OAuthValidator {
    config: OAuthConfig,
    client: reqwest::Client,
    // Cache of JWKS keys
    keys: tokio::sync::RwLock<HashMap<String, DecodingKey>>,
}

#[cfg(feature = "oauth")]
impl OAuthValidator {
    /// Creates a new `OAuthValidator` with the given configuration.
    ///
    /// Note: This does *not* automatically fetch the JWKS. You must call 
    /// [`refresh_keys`](Self::refresh_keys) before validating any tokens.
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            keys: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Fetches the JWKS from the configured provider URL and updates the internal key cache.
    ///
    /// This method clears the existing cache and replaces it with the freshly downloaded keys.
    /// It safely handles all standard JWK parameters and key types (RSA, EC, etc.) via the
    /// `jsonwebtoken` crate's `DecodingKey::from_jwk`.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError::Http`] if the network request fails, or an [`OAuthError::Jwt`]
    /// if the response body cannot be parsed as a valid JWKS.
    pub async fn refresh_keys(&self) -> Result<(), OAuthError> {
        let resp = self.client.get(&self.config.jwks_url).send().await?;
        
        // Deserialize directly into jsonwebtoken's JwkSet.
        // This safely handles all standard JWK parameters and key types (RSA, EC, etc.).
        let jwks: JwkSet = resp.json().await?;
        
        let mut keys = self.keys.write().await;
        keys.clear();
        
        for jwk in jwks.keys {
            if let Some(kid) = &jwk.common.key_id {
                // Use from_jwk which safely constructs the DecodingKey 
                // from the JWK, handling base64url decoding and key type validation internally.
                let decoding_key = DecodingKey::from_jwk(&jwk)
                    .map_err(|_| OAuthError::Jwt(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into()))?;
                
                keys.insert(kid.clone(), decoding_key);
            }
        }
        Ok(())
    }

    /// Validates an OAuth2 / OIDC JWT string and extracts the verified claims.
    ///
    /// This method performs the following steps:
    /// 1. Decodes the JWT header to extract the `kid` (Key ID).
    /// 2. Looks up the corresponding `DecodingKey` in the internal cache.
    /// 3. Verifies the cryptographic signature using the matched key.
    /// 4. Validates standard claims (`exp`, `iss`, `aud`) against the [`OAuthConfig`].
    ///
    /// # Arguments
    ///
    /// * `token` - The compact JWT string (without the "Bearer " prefix).
    ///
    /// # Returns
    ///
    /// The decoded and verified [`Claims`] payload.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if:
    /// - The token header is malformed or missing a `kid`.
    /// - The `kid` is not present in the cached JWKS (you may need to call `refresh_keys`).
    /// - The signature is invalid.
    /// - The token is expired, or the `iss`/`aud` claims do not match the configuration.
    pub async fn validate_token(&self, token: &str) -> Result<Claims, OAuthError> {
        // 1. Decode header to get kid
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(OAuthError::InvalidKey)?;
        
        // 2. Lookup key in cache
        let keys = self.keys.read().await;
        let decoding_key = keys.get(&kid).ok_or(OAuthError::InvalidKey)?;

        // 3. Configure validation rules
        let mut validation = Validation::default();
        
        // Restrict to configured algorithms to prevent algorithm confusion attacks.
        // This allows the validator to support key rotation to different algorithms (e.g., RS384, ES256).
        validation.algorithms = self.config.algorithms.clone();
        
        if let Some(aud) = &self.config.audience {
            validation.set_audience(&[aud]);
        }
        validation.set_issuer(&[&self.config.issuer]);

        // 4. Decode and verify signature + claims
        let data = decode::<Claims>(token, decoding_key, &validation)?;
        Ok(data.claims)
    }
}
