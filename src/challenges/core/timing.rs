//! Adaptive timing utilities.
//!
//! These abstractions provide a simplified feedback-driven delay system that
//! solvers and the pipeline can reuse as a foundation for dynamic delays.

use std::cmp::Ordering;
use std::time::Duration;

/// Feedback emitted after solving attempts.
#[derive(Debug, Clone, Copy)]
pub enum TimingFeedback {
    Success,
    Failure,
    RateLimited,
}

/// Strategies used to compute the next delay before replaying a challenge.
#[derive(Debug, Clone)]
pub struct DelayStrategy {
    base_delay_ms: u64,
    min_delay_ms: u64,
    max_delay_ms: u64,
    variance_pct: f64,
    recent_failures: u32,
}

impl DelayStrategy {
    pub fn new(base_delay_ms: u64) -> Self {
        Self {
            base_delay_ms,
            min_delay_ms: base_delay_ms / 2,
            max_delay_ms: base_delay_ms * 2,
            variance_pct: 0.25,
            recent_failures: 0,
        }
    }

    pub fn with_bounds(mut self, min_delay_ms: u64, max_delay_ms: u64) -> Self {
        self.min_delay_ms = min_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    pub fn with_variance(mut self, variance_pct: f64) -> Self {
        self.variance_pct = variance_pct;
        self
    }

    pub fn register_feedback(&mut self, feedback: TimingFeedback) {
        match feedback {
            TimingFeedback::Success => {
                self.recent_failures = self.recent_failures.saturating_sub(1);
            }
            TimingFeedback::Failure => {
                self.recent_failures = self.recent_failures.saturating_add(1);
            }
            TimingFeedback::RateLimited => {
                self.recent_failures = self.recent_failures.saturating_add(2);
            }
        }
    }

    pub fn next_delay(&self) -> Duration {
        let mut delay = self.base_delay_ms as f64;

        match self.recent_failures.cmp(&2) {
            Ordering::Less => {}
            Ordering::Equal => delay *= 1.5,
            Ordering::Greater => delay *= 2.0,
        }

        let variance = delay * self.variance_pct;
        let jitter = rand::random::<f64>() * variance - (variance / 2.0);
        delay = (delay + jitter).clamp(self.min_delay_ms as f64, self.max_delay_ms as f64);
        Duration::from_millis(delay.max(0.0) as u64)
    }
}
