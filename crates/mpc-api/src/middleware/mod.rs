//! # API Gateway Middleware
//!
//! This module contains the Axum middleware stack applied to the MPC-RS API Gateway.
//! It provides cross-cutting concerns such as authentication, authorization, and 
//! resource protection (rate limiting) before requests reach the core business logic.
//!
//! ## Middleware Execution Order
//! Middleware in Axum is executed in the order it is layered. Typically, rate limiting 
//! is applied *before* authentication to protect the JWT validation logic from being 
//! overwhelmed by unauthenticated traffic, though both are applied at the router level 
//! in this architecture.

pub mod auth;
pub mod ratelimit;
