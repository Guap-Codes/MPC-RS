//! # Tonic gRPC Authentication Middleware
//!
//! This module provides a Tonic [`Interceptor`](tonic::service::Interceptor) for 
//! authenticating incoming gRPC requests using JSON Web Tokens (JWTs).
//!
//! ## Feature Flag
//! This module is only compiled when the `tonic-middleware` feature is enabled in 
//! your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! mpc-auth = { version = "0.1", features = ["tonic-middleware"] }
//! ```
//!
//! ## Security Context
//! In the MPC-RS architecture, gRPC endpoints (such as the Coordinator's administrative 
//! API) must enforce **Scope-Bound JWT Authentication**. This interceptor ensures that:
//! 1. Every request contains a valid `Authorization: Bearer <token>` header.
//! 2. The token's cryptographic signature is valid and unexpired.
//! 3. The token's audience (`aud`) and issuer (`iss`) match the strict expectations 
//!    configured in the [`JwtManager`].
//! 4. The validated [`Claims`] are securely injected into the request's extension map, 
//!    allowing downstream RPC handlers to perform Role-Based Access Control (RBAC) checks.

#[cfg(feature = "tonic-middleware")]
use tonic::{Request, Status};
#[cfg(feature = "tonic-middleware")]
use crate::jwt::JwtManager;
#[cfg(feature = "tonic-middleware")]
use crate::claims::Claims;
#[cfg(feature = "tonic-middleware")]
use std::sync::Arc;

/// A Tonic interceptor that validates JWTs and injects claims into request extensions.
///
/// `AuthInterceptor` acts as a gatekeeper for your gRPC services. It intercepts every
/// incoming request, extracts the Bearer token from the `authorization` metadata header,
/// validates it using the provided [`JwtManager`], and inserts the resulting [`Claims`]
/// into the request's extension typemap.
///
/// # Example: Wiring into a Tonic Server
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use mpc_auth::jwt::JwtManager;
/// use mpc_auth::middleware::AuthInterceptor;
/// use jsonwebtoken::Algorithm;
/// use tonic::transport::Server;
/// // use your_crate::proto::my_service_server::{MyService, MyServiceServer};
///
/// # async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
/// let public_pem = include_bytes!("../../../config/public.pem");
/// let jwt_manager = Arc::new(JwtManager::new(Algorithm::RS256, public_pem, None)?);
///
/// // Create the interceptor
/// let auth_interceptor = AuthInterceptor::new(jwt_manager);
///
/// // let my_service = MyServiceImpl::default();
///
/// // Server::builder()
/// //     .add_service(MyServiceServer::with_interceptor(my_service, auth_interceptor))
/// //     .serve("127.0.0.1:50051".parse()?)
/// //     .await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "tonic-middleware")]
pub struct AuthInterceptor {
    /// The shared JWT manager containing the decoding keys and validation rules.
    jwt_manager: Arc<JwtManager>,
}

#[cfg(feature = "tonic-middleware")]
impl AuthInterceptor {
    /// Creates a new `AuthInterceptor` with the given JWT manager.
    ///
    /// # Arguments
    ///
    /// * `jwt_manager` - An `Arc`-wrapped [`JwtManager`] configured with the expected 
    ///   algorithm, public key, and validation rules (e.g., expected audience).
    #[must_use]
    pub const fn new(jwt_manager: Arc<JwtManager>) -> Self {
        Self { jwt_manager }
    }
}

#[cfg(feature = "tonic-middleware")]
impl tonic::service::Interceptor for AuthInterceptor {
    /// Intercepts a gRPC request to validate the JWT Bearer token.
    ///
    /// This method performs the following steps:
    /// 1. Extracts the `authorization` header from the gRPC metadata.
    /// 2. Strips the `"Bearer "` prefix to isolate the raw JWT string.
    /// 3. Passes the token to the [`JwtManager`] for cryptographic and temporal validation.
    /// 4. Inserts the validated [`Claims`] into the request's extensions map.
    ///
    /// # Errors
    ///
    /// Returns a [`Status::unauthenticated`] error if:
    /// - The `authorization` header is missing or not valid UTF-8.
    /// - The header does not start with `"Bearer "`.
    /// - The JWT is malformed, expired, has an invalid signature, or fails audience/issuer checks.
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let claims = self
            .jwt_manager
            .validate_token(token)
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))?;

        // Insert claims into request extensions for later use
        request.extensions_mut().insert(claims);
        Ok(request)
    }
}

/// Extracts the validated [`Claims`] from a Tonic request's extensions.
///
/// After the [`AuthInterceptor`] successfully validates a token, it stores the 
/// resulting [`Claims`] in the request's extension typemap. Downstream RPC handlers 
/// can use this convenience function to retrieve the claims and perform Role-Based 
/// Access Control (RBAC) checks.
///
/// # Arguments
///
/// * `req` - A reference to the incoming Tonic [`Request`].
///
/// # Returns
///
/// A reference to the [`Claims`] if they were successfully injected by the interceptor.
///
/// # Errors
///
/// Returns a [`Status::unauthenticated`] error if the claims are missing from the 
/// extensions map (which typically indicates the request bypassed the `AuthInterceptor`).
///
/// # Example: Using in an RPC Handler
///
/// ```rust,no_run
/// use mpc_auth::middleware::get_claims;
/// use mpc_auth::claims::Claims;
/// use tonic::{Request, Response, Status};
/// // use your_crate::proto::{MyMessage, Empty};
///
/// // #[tonic::async_trait]
/// // impl MyService for MyServiceImpl {
/// //     async fn admin_only_rpc(
/// //         &self,
/// //         request: Request<MyMessage>,
/// //     ) -> Result<Response<Empty>, Status> {
/// //         // 1. Extract the claims
/// //         let claims = get_claims(&request)?;
/// //
/// //         // 2. Enforce RBAC
/// //         if !claims.has_role("admin") {
/// //             return Err(Status::permission_denied("admin role required"));
/// //         }
/// //
/// //         // 3. Process the request
/// //         Ok(Response::new(Empty {}))
/// //     }
/// // }
/// ```
#[cfg(feature = "tonic-middleware")]
pub fn get_claims<T>(req: &Request<T>) -> Result<&Claims, Status> {
    req.extensions()
        .get::<Claims>()
        .ok_or_else(|| Status::unauthenticated("claims not found"))
}
