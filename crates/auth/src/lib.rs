//! # MPC-RS Authentication & Authorization (`mpc-auth`)
//!
//! This crate provides the centralized authentication, authorization, and 
//! identity validation layer for the MPC-RS institutional custody ecosystem.
//!
//! ## Security Architecture: Scope-Bound JWTs
//! In a zero-trust MPC architecture, preventing **Cross-Service Token Replay Attacks** 
//! is critical. A token minted for a user to submit transactions to the public API Gateway 
//! (`aud: "mpc-api"`) must be cryptographically rejected if an attacker attempts to use it 
//! to trigger administrative DKG ceremonies on the internal Coordinator (`aud: "mpc-coordinator"`).
//!
//! This crate enforces strict audience (`aud`) and issuer (`iss`) validation by default, 
//! alongside Role-Based Access Control (RBAC) via the [`Claims`] struct.
//!
//! ## Cargo Feature Flags
//! To keep the dependency tree lightweight for microservices that only need basic JWT 
//! validation, advanced integrations are gated behind Cargo features:
//!
//! | Feature              | Description                                                                 | Dependencies Added      |
//! |----------------------|-----------------------------------------------------------------------------|-------------------------|
//! | *(default)*          | Core JWT creation/validation and RBAC claims.                               | `jsonwebtoken`, `serde` |
//! | `oauth`              | Enables asynchronous OIDC/OAuth2 JWKS validation for external providers.    | `reqwest`, `tokio`      |
//! | `tonic-middleware`   | Enables gRPC [`Interceptor`](tonic::service::Interceptor) for Tonic servers.| `tonic`                 |
//!
//! ## Quick Start
//!
//! ### 1. Minting and Validating Tokens (API Gateway)
//! ```rust,no_run
//! use mpc_auth::{JwtManager, Claims};
//! use jsonwebtoken::Algorithm;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let private_pem = include_bytes!("../../../config/private.pem");
//! let public_pem = include_bytes!("../../../config/public.pem");
//!
//! // Initialize manager with both keys to allow signing and validating
//! let manager = JwtManager::new(Algorithm::RS256, public_pem, Some(private_pem))?;
//!
//! // Mint a token for an admin (valid for 1 hour)
//! let claims = Claims::new("ops_team", vec!["admin".to_string()], 3600);
//! let token = manager.create_token(&claims)?;
//!
//! // Validate the token (strictly checks exp, iss, and aud)
//! let verified_claims = manager.validate_token(&token)?;
//! assert!(verified_claims.has_role("admin"));
//! # Ok(())
//! # }
//! ```
//!
//! ### 2. Securing gRPC Endpoints (Coordinator)
//! Enable the `tonic-middleware` feature to protect Tonic services:
//! ```toml
//! [dependencies]
//! mpc-auth = { version = "0.1", features = ["tonic-middleware"] }
//! ```
//! ```rust,ignore
//! use mpc_auth::middleware::AuthInterceptor;
//! // See `mpc_auth::middleware` documentation for full Tonic server wiring.
//! ```

pub mod claims;
pub mod jwt;

/// Asynchronous OAuth2 / OIDC token validation using JWKS.
///
/// This module is only available when the `oauth` feature is enabled.
/// It provides the [`oauth::OAuthValidator`] for validating tokens issued 
/// by external identity providers (e.g., Auth0, Okta, Keycloak).
#[cfg(feature = "oauth")]
pub mod oauth;

/// Tonic gRPC authentication interceptors.
///
/// This module is only available when the `tonic-middleware` feature is enabled.
/// It provides the [`middleware::AuthInterceptor`] to automatically validate 
/// Bearer tokens on incoming gRPC requests and inject the verified [`Claims`] 
/// into the request extensions for downstream RBAC checks.
#[cfg(feature = "tonic-middleware")]
pub mod middleware;

// ==============================================================================
// Ergonomic Re-exports
// ==============================================================================

// Re-export the core JWT payload structure so downstream crates can easily 
// perform RBAC checks (e.g., `claims.has_role("admin")`) without deep imports.
pub use claims::Claims;

// Re-export the stateful JWT manager and its error type for ergonomic access.
// This allows users to write `use mpc_auth::JwtManager;` instead of 
// `use mpc_auth::jwt::JwtManager;`.
pub use jwt::{JwtError, JwtManager};

// Conditionally re-export the OAuth validator if the feature is active.
#[cfg(feature = "oauth")]
pub use oauth::{OAuthConfig, OAuthError, OAuthValidator};

// Conditionally re-export the Tonic interceptor and claims extractor.
#[cfg(feature = "tonic-middleware")]
pub use middleware::{AuthInterceptor, get_claims};

