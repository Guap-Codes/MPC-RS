//! # Rate Limiting Middleware (Token Bucket)
//!
//! This module implements a Token Bucket rate limiting algorithm to protect the 
//! API Gateway from abuse, brute-force attacks, and resource exhaustion.
//!
//! ## Algorithm
//! Each client IP address is assigned a "bucket" with a maximum capacity of tokens.
//! Tokens are consumed on each request. If the bucket is empty, the request is 
//! rejected with `429 Too Many Requests`. Tokens are continuously replenished at 
//! a fixed rate, up to the maximum capacity.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::AppState;

/// Represents the state of a single client's rate limit bucket.
struct TokenBucket {
    /// The current number of available tokens.
    tokens: u32,
    /// The timestamp of the last token replenishment calculation.
    last_refill: Instant,
}

/// Shared state for the rate limiting middleware.
///
/// This struct is wrapped in an `Arc` and shared across all concurrent requests 
/// via Axum's `State` extractor.
pub struct RateLimitState {
    /// A thread-safe map of client IP addresses to their respective token buckets.
    limits: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    /// The maximum number of tokens a bucket can hold (burst capacity).
    capacity: u32,
    /// The time duration required to generate a single new token.
    refill_rate: Duration,
}

impl RateLimitState {
    /// Creates a new `RateLimitState` with the specified capacity and refill rate.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The maximum number of requests allowed in a burst.
    /// * `per_seconds` - The time window (in seconds) over which the `capacity` is replenished.
    ///
    /// # Note
    ///
    /// The `refill_rate` is calculated as `per_seconds / capacity`. For example, 
    /// a capacity of `10` and `per_seconds` of `60` results in 1 token being 
    /// added every 6 seconds.
    pub fn new(capacity: u32, per_seconds: u64) -> Self {
        let refill_rate = Duration::from_secs_f64(per_seconds as f64 / capacity as f64);
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            capacity,
            refill_rate,
        }
    }
}

/// Axum middleware that enforces per-IP rate limiting using the Token Bucket algorithm.
///
/// # Workflow
/// 1. Extracts the client's IP address, prioritizing the `x-forwarded-for` header 
///    (to support reverse proxies/load balancers), falling back to `127.0.0.1`.
/// 2. Acquires a lock on the shared `HashMap` of token buckets.
/// 3. Initializes a new bucket with full capacity if the IP is unseen.
/// 4. Calculates and applies token replenishment based on the elapsed time.
/// 5. If tokens are available, decrements the count and allows the request.
/// 6. If tokens are depleted, returns `429 Too Many Requests`.
///
/// # Arguments
///
/// * `state` - The shared application state, from which the `RateLimitState` is extracted.
/// * `request` - The incoming HTTP request.
/// * `next` - The next middleware or handler in the Axum stack.
///
/// # Returns
///
/// * `Ok(Response)` - If the request is within the rate limit.
/// * `Err(StatusCode::TOO_MANY_REQUESTS)` - If the client has exhausted their token bucket.
pub async fn rate_limit_middleware(
    // Extract the full `AppState` instead of just `Arc<RateLimitState>`
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the specific rate limit state from the global AppState
    let rate_limit_state = &state.rate_limit_state;

    // Extract client IP, handling reverse proxy headers safely
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        // Take the first IP in the comma-separated list (the original client)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        // Fallback to localhost if header is missing or malformed
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    // Acquire the mutex lock to safely mutate the bucket state
    let mut buckets = rate_limit_state.limits.lock().await;
    let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
        tokens: rate_limit_state.capacity,
        last_refill: Instant::now(),
    });

    let now = Instant::now();
    let elapsed = now.duration_since(bucket.last_refill);
    
    // Calculate how many tokens to add based on elapsed time
    let refill = (elapsed.as_secs_f64() / rate_limit_state.refill_rate.as_secs_f64()) as u32;
    if refill > 0 {
        bucket.tokens = (bucket.tokens + refill).min(rate_limit_state.capacity);
        bucket.last_refill = now;
    }

    // Check if the bucket is empty
    if bucket.tokens == 0 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    // Consume one token for this request
    bucket.tokens -= 1;
    
    // Explicitly drop the lock before awaiting the next handler to prevent 
    // blocking other concurrent requests while the handler executes.
    drop(buckets);

    Ok(next.run(request).await)
}

