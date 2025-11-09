//! JavaScript interpreter infrastructure.
//!
//! Provides a shared trait and error type used by JavaScript-based challenge
//! solvers, along with concrete runtime implementations.

mod boa;

pub use boa::BoaJavascriptInterpreter;

use thiserror::Error;

/// Abstraction over JavaScript runtimes capable of solving Cloudflare logic.
pub trait JavascriptInterpreter: Send + Sync {
    /// Evaluate a challenge page and return the solved answer formatted with
    /// 10 decimal places.
    fn solve_challenge(&self, page_html: &str, host: &str) -> Result<String, InterpreterError>;

    /// Execute raw JavaScript within a pre-constructed environment.
    fn execute(&self, script: &str, host: &str) -> Result<String, InterpreterError> {
        let _ = (script, host);
        Err(InterpreterError::Other("execute not implemented".into()))
    }
}

/// Failures produced by JavaScript runtimes.
#[derive(Debug, Error)]
pub enum InterpreterError {
    #[error("javascript execution failed: {0}")]
    Execution(String),
    #[error("javascript engine error: {0}")]
    Other(String),
}

/// Convenience alias for runtime results.
pub type InterpreterResult<T> = Result<T, InterpreterError>;
