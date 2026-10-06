//! # Policy Evaluation Engine
//!
//! This module defines the core logic for evaluating transaction requests against
//! a set of configurable rules. It aggregates the results of all rules to provide
//! a comprehensive pass/fail decision, including all reasons for denial.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::rules::{Rule, RuleDecision};

/// The complete context required to evaluate a transaction against policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The target blockchain network (e.g., "ethereum", "bitcoin").
    pub chain: String,
    /// The source address of the transaction.
    pub from_address: String,
    /// The destination address of the transaction.
    pub to_address: String,
    /// The transaction amount in the smallest chain unit (e.g., wei, satoshi).
    pub amount_smallest_unit: u64,
    /// Optional token contract address (e.g., for ERC-20 transfers).
    pub token: Option<String>,
    /// The UTC timestamp of the request.
    pub timestamp: DateTime<Utc>,
    /// The authenticated user's subject (from JWT claims), used for identity-based rules.
    pub initiator_subject: Option<String>,
    /// Free-form metadata (e.g., request ID, client IP, user agent).
    pub metadata: serde_json::Value,
}

/// The aggregated result of evaluating a `PolicyContext` against all rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// `true` if the transaction is allowed; `false` if denied.
    pub allowed: bool,
    /// A list of human-readable reasons from all failing rules.
    pub reasons: Vec<String>,
    /// A list of rule IDs that were evaluated during this check.
    pub rules_checked: Vec<String>,
}

/// The policy evaluator that holds and executes a list of rules.
pub struct PolicyEvaluator {
    rules: Vec<Box<dyn Rule>>,
}

impl PolicyEvaluator {
    /// Creates a new, empty `PolicyEvaluator`.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a new rule to the evaluator.
    ///
    /// # Arguments
    ///
    /// * `rule` - Any type implementing the `Rule` trait.
    pub fn add_rule<R: Rule + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }

    /// Evaluates the given context against all registered rules.
    ///
    /// # Note
    ///
    /// This method evaluates **all** rules, even if one fails early. This is a
    /// deliberate design choice to collect *all* denial reasons, providing the user
    /// or auditor with a complete picture of why the transaction was rejected,
    /// rather than just the first failing rule.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The `PolicyContext` containing the transaction details.
    ///
    /// # Returns
    ///
    /// A `PolicyResult` indicating whether the transaction is allowed and listing
    /// any denial reasons.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult {
        let mut reasons = Vec::new();
        let mut rules_checked = Vec::new();
        let mut allowed = true;

        for rule in &self.rules {
            let id = rule.id().to_string();
            rules_checked.push(id.clone());
            match rule.evaluate(ctx) {
                RuleDecision::Allow => {},
                RuleDecision::Deny(reason) => {
                    allowed = false;
                    reasons.push(format!("{}: {}", id, reason));
                }
            }
        }

        PolicyResult {
            allowed,
            reasons,
            rules_checked,
        }
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

