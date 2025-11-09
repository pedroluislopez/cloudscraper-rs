//! Core data structures shared across challenge detection, analysis, and solving layers.

use http::{HeaderMap, Method};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// Minimal representation of an HTTP response emitted by the scraper.
#[derive(Debug, Clone)]
pub struct ChallengeResponse<'a> {
    pub url: &'a Url,
    pub status: u16,
    pub headers: &'a HeaderMap,
    pub body: &'a str,
    pub request_method: &'a Method,
}

/// Planned submission back to Cloudflare once a challenge is solved.
#[derive(Debug, Clone)]
pub struct ChallengeSubmission {
    pub method: Method,
    pub url: Url,
    pub form_fields: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub wait: Duration,
    pub allow_redirects: bool,
}

impl ChallengeSubmission {
    pub fn new(
        method: Method,
        url: Url,
        form_fields: HashMap<String, String>,
        headers: HashMap<String, String>,
        wait: Duration,
    ) -> Self {
        Self {
            method,
            url,
            form_fields,
            headers,
            wait,
            allow_redirects: false,
        }
    }

    pub fn with_allow_redirects(mut self, allow: bool) -> Self {
        self.allow_redirects = allow;
        self
    }
}
