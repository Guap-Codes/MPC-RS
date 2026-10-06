//! # JWT Authentication Middleware
//!
//! This module provides the primary authentication gatekeeper for the API Gateway.
//! It intercepts incoming HTTP requests, extracts the Bearer token, and validates 
//! it against the configured `JwtManager`.
//!
//! ## Security Context
//! Upon successful validation, the decoded `Claims` are injected into the request's 
//! extension map. This allows downstream handlers to perform fine-grained, 
//! Role-Based Access Control (RBAC) checks without re-parsing the token.

use std::sync::Arc;
use axum::{
    extract::{Request, State}, 
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::AppState;

/// Axum middleware that enforces JWT Bearer token authentication.
///
/// # Workflow
/// 1. Extracts the `Authorization` header from the incoming request.
/// 2. Strips the `"Bearer "` prefix to isolate the raw token string.
/// 3. Validates the token's signature, expiration, issuer, and audience via `JwtManager`.
/// 4. On success, injects the validated `Claims` into `request.extensions()` and proceeds.
/// 5. On failure (missing header, invalid format, or validation error), returns `401 Unauthorized`.
///
/// # Arguments
///
/// * `state` - The shared application state containing the `JwtManager`.
/// * `request` - The incoming HTTP request.
/// * `next` - The next middleware or handler in the Axum stack.
///
/// # Returns
///
/// * `Ok(Response)` - If the token is valid, the processed response from the next handler.
/// * `Err(StatusCode::UNAUTHORIZED)` - If the token is missing, malformed, or invalid.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    match token {
        Some(t) => {
            match state.jwt_manager.validate_token(t) {
                Ok(claims) => {
                    // Insert the validated claims into the request extensions
                    // so that downstream handlers can extract them for RBAC checks.
                    request.extensions_mut().insert(claims);
                    Ok(next.run(request).await)
                }
                Err(_) => Err(StatusCode::UNAUTHORIZED),
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

