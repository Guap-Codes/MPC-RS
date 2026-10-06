//! # API Routing Structure
//!
//! This module organizes the HTTP routing structure for the MPC-RS API Gateway.
//! It separates public endpoints (e.g., health checks) from protected endpoints 
//! (e.g., wallet operations) to allow for targeted, layered middleware application.
//!
//! ## Routing Strategy
//! - **Public Routes**: Defined in the `health` module, these bypass authentication 
//!   and rate limiting to ensure infrastructure monitoring remains reliable.
//! - **Protected Routes**: Defined in the `wallet` module, these are wrapped in 
//!   `auth_middleware` and `rate_limit_middleware` at the application level in `main.rs`.

pub mod health;
pub mod wallet;