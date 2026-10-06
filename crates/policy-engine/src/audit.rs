//! # Policy Audit Logging
//!
//! This module bridges the policy evaluation engine with the system's tamper-evident
//! audit log. It ensures that every transaction approval or denial is cryptographically
//! chained, providing a verifiable trail for compliance, forensic analysis, and regulatory reporting.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use mpc_common::types::{SessionId, EventType};
use mpc_common::audit::AuditEvent;
use crate::evaluator::{PolicyContext, PolicyResult};

/// Represents a single policy evaluation outcome.
///
/// This struct captures the exact context and result of a policy check,
/// serving as the payload for the cryptographically chained audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditRecord {
    /// Unique identifier for this specific audit record.
    pub id: Uuid,
    /// The exact UTC timestamp when the evaluation occurred.
    pub timestamp: DateTime<Utc>,
    /// The MPC session this evaluation is associated with (if applicable).
    pub session_id: Option<SessionId>,
    /// Arbitrary metadata about the request (e.g., client IP, request ID).
    pub request_metadata: serde_json::Value,
    /// The aggregated result of the policy evaluation.
    pub policy_result: PolicyResult,
}

impl PolicyAuditRecord {
    /// Converts this record into a standard, cryptographically chained `AuditEvent`.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The HMAC secret key used to secure the audit chain.
    /// * `prev_event` - A reference to the immediately preceding audit event (for chaining).
    ///
    /// # Returns
    ///
    /// An `AuditEvent` containing the serialized policy record, ready to be appended
    /// to the immutable audit log.
    pub fn to_audit_event(
        &self,
        secret_key: &[u8],
        prev_event: Option<&AuditEvent>,
    ) -> AuditEvent {
        AuditEvent::new(
            EventType::PolicyEvaluation,
            self.session_id.unwrap_or_else(|| SessionId(Uuid::nil())),
            None, // party_id is not applicable at the API gateway policy layer
            serde_json::to_value(self).unwrap_or_default(),
            prev_event,
            secret_key,
        )
    }
}

/// A utility for generating audit events from policy decisions.
pub struct PolicyAuditLogger;

impl PolicyAuditLogger {
    /// Produces a chained audit event for a specific policy evaluation.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The MPC session ID associated with this request.
    /// * `ctx` - The `PolicyContext` containing the transaction details.
    /// * `result` - The `PolicyResult` produced by the evaluator.
    /// * `secret_key` - The HMAC secret key for the audit chain.
    /// * `prev_event` - The preceding audit event for cryptographic chaining.
    ///
    /// # Returns
    ///
    /// A fully populated and signed `AuditEvent`.
    pub fn log(
        session_id: Option<SessionId>,
        ctx: &PolicyContext,
        result: &PolicyResult,
        secret_key: &[u8],
        prev_event: Option<&AuditEvent>,
    ) -> AuditEvent {
        let record = PolicyAuditRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            session_id,
            request_metadata: ctx.metadata.clone(),
            policy_result: result.clone(),
        };
        record.to_audit_event(secret_key, prev_event)
    }
}
