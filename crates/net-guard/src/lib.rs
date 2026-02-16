//! # net-guard
//!
//! Network binding enforcement for OpenClaw. This crate ensures that OpenClaw
//! only binds to localhost, preventing accidental exposure on all interfaces.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use net_guard::{BindConfig, enforce_bind_env, verify_bind};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = BindConfig::default(); // 127.0.0.1:18790
//!
//! // Get env vars to pass to the OpenClaw child process
//! let env_overrides = enforce_bind_env(&config);
//!
//! // After spawning, verify the process actually bound to localhost
//! let is_bound = verify_bind(&config.internal_addr).await?;
//! # Ok(())
//! # }
//! ```

mod guard;

pub use guard::{enforce_bind_env, verify_bind, BindConfig, BindError};
