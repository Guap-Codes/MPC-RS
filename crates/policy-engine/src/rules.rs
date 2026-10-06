//! # Policy Rules
//!
//! This module defines the `Rule` trait and provides a set of built-in rules
//! commonly required for institutional cryptocurrency custody (e.g., amount limits,
//! address whitelists, time windows, and identity checks).

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, NaiveTime};
use std::collections::HashSet;
use crate::evaluator::PolicyContext;

/// The decision returned by a single policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDecision {
    /// The transaction is allowed by this rule.
    Allow,
    /// The transaction is denied by this rule, with a human-readable reason.
    Deny(String),
}

/// The core trait that all policy rules must implement.
pub trait Rule: Send + Sync {
    /// Returns a unique identifier for this rule (used in audit logs).
    fn id(&self) -> &str;

    /// Evaluates the rule against the given transaction context.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The `PolicyContext` containing the transaction details.
    ///
    /// # Returns
    ///
    /// A `RuleDecision` indicating whether the rule allows or denies the transaction.
    fn evaluate(&self, ctx: &PolicyContext) -> RuleDecision;
}

// ---------------------------------------------------------------------------
// Built-in Rules
// ---------------------------------------------------------------------------

/// Restricts the maximum amount allowed in a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxTransactionAmount {
    pub id: String,
    /// The maximum allowed amount in the smallest chain unit (e.g., wei, satoshi).
    pub max_amount: u64,
}

impl MaxTransactionAmount {
    /// Creates a new `MaxTransactionAmount` rule.
    pub fn new(id: &str, max_amount: u64) -> Self {
        Self { id: id.to_string(), max_amount }
    }
}

impl Rule for MaxTransactionAmount {
    fn id(&self) -> &str { &self.id }

    fn evaluate(&self, ctx: &PolicyContext) -> RuleDecision {
        if ctx.amount_smallest_unit <= self.max_amount {
            RuleDecision::Allow
        } else {
            RuleDecision::Deny(format!(
                "amount {} exceeds max {} per transaction",
                ctx.amount_smallest_unit, self.max_amount
            ))
        }
    }
}

/// Restricts the cumulative transaction volume over a rolling time window.
///
/// # Note
///
/// This is a placeholder implementation. A production-ready version would require
/// querying a time-series database or Redis to track historical volume. It is
/// included here to demonstrate the rule interface for stateful checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxRollingVolume {
    pub id: String,
    pub max_total: u64,
    pub window_seconds: i64,
}

impl MaxRollingVolume {
    /// Creates a new `MaxRollingVolume` rule.
    pub fn new(id: &str, max_total: u64, window_seconds: i64) -> Self {
        Self { id: id.to_string(), max_total, window_seconds }
    }
}

impl Rule for MaxRollingVolume {
    fn id(&self) -> &str { &self.id }

    fn evaluate(&self, _ctx: &PolicyContext) -> RuleDecision {
        // Placeholder: Always allow. Implement external state tracking for production.
        RuleDecision::Allow
    }
}

/// Restricts transactions to specific hours of the day (UTC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub id: String,
    /// The start hour of the allowed window (0-23).
    pub start_hour: u32,
    /// The end hour of the allowed window (0-23).
    pub end_hour: u32,
}

impl TimeWindow {
    /// Creates a new `TimeWindow` rule.
    pub fn new(id: &str, start_hour: u32, end_hour: u32) -> Self {
        Self { id: id.to_string(), start_hour, end_hour }
    }
}

impl Rule for TimeWindow {
    fn id(&self) -> &str { &self.id }

    fn evaluate(&self, ctx: &PolicyContext) -> RuleDecision {
        let now = ctx.timestamp.time();
        let start = NaiveTime::from_hms_opt(self.start_hour, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(self.end_hour, 0, 0).unwrap();
        
        if now >= start && now <= end {
            RuleDecision::Allow
        } else {
            RuleDecision::Deny(format!(
                "current time {:?} outside allowed window {:?}-{:?}",
                now, start, end
            ))
        }
    }
}

/// Restricts transactions to a predefined whitelist of addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressWhitelist {
    pub id: String,
    /// The set of allowed addresses.
    pub whitelist: HashSet<String>,
    /// If `true`, only the `to_address` is checked. If `false`, both `from` and `to` must be whitelisted.
    pub to_only: bool,
}

impl AddressWhitelist {
    /// Creates a new `AddressWhitelist` rule.
    pub fn new(id: &str, whitelist: Vec<String>, to_only: bool) -> Self {
        Self { 
            id: id.to_string(), 
            whitelist: whitelist.into_iter().collect(), 
            to_only 
        }
    }
}

impl Rule for AddressWhitelist {
    fn id(&self) -> &str { &self.id }

    fn evaluate(&self, ctx: &PolicyContext) -> RuleDecision {
        let to_ok = self.whitelist.contains(&ctx.to_address);
        let from_ok = self.whitelist.contains(&ctx.from_address);
        let allowed = if self.to_only {
            to_ok
        } else {
            to_ok && from_ok
        };
        
        if allowed {
            RuleDecision::Allow
        } else {
            RuleDecision::Deny(format!(
                "address not in whitelist: from={} to={}",
                ctx.from_address, ctx.to_address
            ))
        }
    }
}

/// Requires the transaction initiator to match a specific set of authorized identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverIdentity {
    pub id: String,
    /// The set of allowed JWT subject claims (e.g., user IDs or roles).
    pub allowed_subjects: HashSet<String>,
}

impl ApproverIdentity {
    /// Creates a new `ApproverIdentity` rule.
    pub fn new(id: &str, subjects: Vec<String>) -> Self {
        Self { 
            id: id.to_string(), 
            allowed_subjects: subjects.into_iter().collect() 
        }
    }
}

impl Rule for ApproverIdentity {
    fn id(&self) -> &str { &self.id }

    fn evaluate(&self, ctx: &PolicyContext) -> RuleDecision {
        if let Some(subject) = &ctx.initiator_subject
            && self.allowed_subjects.contains(subject) {
            return RuleDecision::Allow;
        }
        RuleDecision::Deny("initiator not authorized".to_string())
    }
}

