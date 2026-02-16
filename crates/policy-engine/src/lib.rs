//! # policy-engine
//!
//! Core security logic for the safety-mitts proxy.  This crate loads YAML
//! policy files, pre-compiles matcher patterns, and evaluates incoming
//! messages against a tiered rule set.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use policy_engine::{PolicyEngine, loader};
//!
//! let config = loader::load_policy("policy.yaml").unwrap();
//! let engine = PolicyEngine::new(config).unwrap();
//! let decision = engine.evaluate_command("rm -rf /");
//! println!("{:?}", decision);
//! ```

mod decision;
mod evaluator;
pub mod loader;
pub mod matcher;
mod schema;

// Re-export primary public API at crate root.
pub use decision::{PolicyDecision, ResolvedAction};
pub use evaluator::PolicyEngine;
pub use schema::{
    DefaultAction, FileOp, Matcher, NetworkPolicy, PolicyConfig, PolicyRule, RuleAction,
};
