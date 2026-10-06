//! # Policy Engine
//!
//! This crate provides the centralized policy enforcement layer for the MPC-RS
//! institutional custody system. It evaluates transaction requests against a
//! configurable set of rules (e.g., amount limits, address whitelists, time windows)
//! and produces cryptographically chained audit logs for every decision.
//!
//! ## Architecture
//! The `PolicyEngine` acts as a facade over the `PolicyEvaluator` and `PolicyAuditLogger`,
//! providing a clean, builder-pattern API for the API Gateway to validate transactions
//! before they are forwarded to the MPC Coordinator for signing.

pub mod rules;
pub mod evaluator;
pub mod audit;

use serde::{Deserialize, Serialize};
use crate::evaluator::{PolicyEvaluator, PolicyContext, PolicyResult};
use crate::audit::PolicyAuditLogger;

/// The main policy engine that holds a set of rules and evaluates transactions.
///
/// This struct combines the rule evaluation logic with the audit logging mechanism,
/// ensuring that every policy check is both enforced and recorded.
pub struct PolicyEngine {
    evaluator: PolicyEvaluator,
    /// Secret key used for audit log HMAC chaining.
    audit_secret: Vec<u8>,
}

impl PolicyEngine {
    /// Creates a new `PolicyEngine` with the specified audit secret.
    ///
    /// # Arguments
    ///
    /// * `audit_secret` - The cryptographic key used to secure the audit log chain.
    pub fn new(audit_secret: Vec<u8>) -> Self {
        Self {
            evaluator: PolicyEvaluator::new(),
            audit_secret,
        }
    }

    /// Adds a rule to the engine using the builder pattern.
    ///
    /// # Arguments
    ///
    /// * `rule` - Any type implementing the `Rule` trait.
    ///
    /// # Returns
    ///
    /// The updated `PolicyEngine` instance.
    pub fn add_rule<R: rules::Rule + 'static>(mut self, rule: R) -> Self {
        self.evaluator.add_rule(rule);
        self
    }

    /// Evaluates a transaction context against all rules.
    ///
    /// # Note
    ///
    /// This method performs the evaluation but does **not** generate an audit log.
    /// Use `evaluate_and_log` if audit compliance is required.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The `PolicyContext` containing the transaction details.
    ///
    /// # Returns
    ///
    /// A `PolicyResult` indicating the evaluation outcome.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult {
        self.evaluator.evaluate(ctx)
    }

    /// Evaluates a transaction context and produces a chained audit event.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The `PolicyContext` containing the transaction details.
    /// * `session_id` - The MPC session ID associated with this request.
    /// * `prev_event` - The preceding audit event for cryptographic chaining.
    ///
    /// # Returns
    ///
    /// A tuple containing the `PolicyResult` and the generated `AuditEvent`.
    pub fn evaluate_and_log(
        &self,
        ctx: &PolicyContext,
        session_id: Option<mpc_common::types::SessionId>,
        prev_event: Option<&mpc_common::audit::AuditEvent>,
    ) -> (PolicyResult, mpc_common::audit::AuditEvent) {
        let result = self.evaluate(ctx);
        let event = PolicyAuditLogger::log(
            session_id,
            ctx,
            &result,
            &self.audit_secret,
            prev_event,
        );
        (result, event)
    }
}
