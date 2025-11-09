//! Integrations that rely on third-party services.
//!
//! This module groups adapters for captcha providers, JavaScript interpreters,
//! and other external dependencies that bridge the core solver with the
//! outside world.

pub mod captcha;
pub mod interpreters;

pub use interpreters::BoaJavascriptInterpreter;
