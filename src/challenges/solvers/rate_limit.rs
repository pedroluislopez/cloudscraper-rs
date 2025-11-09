//! Handler for Cloudflare rate limiting responses (HTTP 1015).
//!
//! Recommends adaptive delays based on headers and page content when 1015
//! responses are encountered.

use std::time::Duration;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::challenges::core::{ChallengeResponse, is_cloudflare_response};

use super::{ChallengeSolver, FailureRecorder, MitigationPlan};

const DEFAULT_DELAY_MIN_SECS: f32 = 60.0;
const DEFAULT_DELAY_MAX_SECS: f32 = 180.0;

/// Advises backoff windows for 1015 responses.
pub struct RateLimitHandler {
    delay_min: Duration,
    delay_max: Duration,
}

impl RateLimitHandler {
    pub fn new() -> Self {
        Self {
            delay_min: Duration::from_secs_f32(DEFAULT_DELAY_MIN_SECS),
            delay_max: Duration::from_secs_f32(DEFAULT_DELAY_MAX_SECS),
        }
    }

    pub fn with_delay_range(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = if max < min { min } else { max };
        self
    }

    pub fn is_rate_limited(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 429
            && RATE_LIMIT_RE.is_match(response.body)
    }

    pub fn plan(
        &self,
        response: &ChallengeResponse<'_>,
        state_recorder: Option<&dyn FailureRecorder>,
    ) -> Result<MitigationPlan, RateLimitError> {
        if !Self::is_rate_limited(response) {
            return Err(RateLimitError::NotRateLimited);
        }

        if let Some(recorder) = state_recorder
            && let Some(domain) = response.url.host_str()
        {
            recorder.record_failure(domain, "cf_rate_limit");
        }

        let (delay, source) = self.determine_delay(response);
        let mut plan = MitigationPlan::retry_after(delay, "rate_limit");
        plan.metadata.insert("delay_source".into(), source);
        plan.metadata.insert("trigger".into(), "cf_1015".into());

        Ok(plan)
    }

    fn determine_delay(&self, response: &ChallengeResponse<'_>) -> (Duration, String) {
        if let Some(delay) = self.retry_after_header(response) {
            return (delay, "header".into());
        }

        if let Some(delay) = self.delay_from_body(response.body) {
            return (delay, "body".into());
        }

        (self.random_delay(), "default".into())
    }

    fn retry_after_header(&self, response: &ChallengeResponse<'_>) -> Option<Duration> {
        use http::header::RETRY_AFTER;

        let raw = response.headers.get(RETRY_AFTER)?.to_str().ok()?;
        if let Ok(seconds) = raw.trim().parse::<f64>()
            && seconds.is_finite()
            && seconds >= 0.0
        {
            return Some(Duration::from_secs_f64(seconds));
        }

        if let Ok(date) = DateTime::parse_from_rfc2822(raw.trim())
            .or_else(|_| DateTime::parse_from_rfc3339(raw.trim()))
            && let Ok(duration) = (date.with_timezone(&Utc) - Utc::now()).to_std()
        {
            return Some(duration);
        }

        None
    }

    fn delay_from_body(&self, body: &str) -> Option<Duration> {
        let caps = RATE_LIMIT_DELAY_RE.captures(body)?;
        let amount: u64 = caps.get(1)?.as_str().parse().ok()?;
        let unit = caps.get(2)?.as_str().to_lowercase();
        let multiplier = match unit.as_str() {
            "second" | "seconds" => 1,
            "minute" | "minutes" => 60,
            "hour" | "hours" => 3600,
            _ => 1,
        };
        Some(Duration::from_secs(amount * multiplier))
    }

    fn random_delay(&self) -> Duration {
        if self.delay_max <= self.delay_min {
            return self.delay_min;
        }
        let mut rng = rand::thread_rng();
        let min = self.delay_min.as_secs_f32();
        let max = self.delay_max.as_secs_f32();
        Duration::from_secs_f32(rng.gen_range(min..max))
    }
}

impl Default for RateLimitHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeSolver for RateLimitHandler {
    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("response is not a Cloudflare rate limit challenge")]
    NotRateLimited,
}

static RATE_LIMIT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r#"(<span[^>]*class=['"]cf-error-code['"]>1015<|rate limited|You are being rate limited)"#,
    )
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .expect("invalid rate limit regex")
});

static RATE_LIMIT_DELAY_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"(\d+)\s*(second|seconds|minute|minutes|hour|hours)"#)
        .case_insensitive(true)
        .build()
        .expect("invalid delay regex")
});

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        HeaderMap, HeaderValue, Method,
        header::{HeaderName, RETRY_AFTER, SERVER},
    };
    use url::Url;

    struct ResponseFixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
        status: u16,
    }

    impl ResponseFixture {
        fn new(body: &str, status: u16) -> Self {
            Self {
                url: Url::parse("https://example.com/rate-limited").unwrap(),
                headers: HeaderMap::new(),
                method: Method::GET,
                body: body.to_string(),
                status,
            }
        }

        fn insert_header(&mut self, name: HeaderName, value: HeaderValue) {
            self.headers.insert(name, value);
        }

        fn response(&self) -> ChallengeResponse<'_> {
            ChallengeResponse {
                url: &self.url,
                status: self.status,
                headers: &self.headers,
                body: &self.body,
                request_method: &self.method,
            }
        }
    }

    #[test]
    fn detects_rate_limit() {
        let mut fixture = ResponseFixture::new(
            "<span class='cf-error-code'>1015</span>You are being rate limited",
            429,
        );
        fixture.insert_header(SERVER, "cloudflare".parse().unwrap());
        let response = fixture.response();
        assert!(RateLimitHandler::is_rate_limited(&response));
    }

    #[test]
    fn plan_uses_retry_after_header() {
        let mut fixture =
            ResponseFixture::new("<span class='cf-error-code'>1015</span> Rate limited", 429);
        fixture.insert_header(SERVER, "cloudflare".parse().unwrap());
        fixture.insert_header(RETRY_AFTER, "120".parse().unwrap());
        let response = fixture.response();
        let handler = RateLimitHandler::new();
        let plan = handler.plan(&response, None).expect("plan");
        assert!(plan.should_retry);
        assert_eq!(plan.wait.unwrap(), Duration::from_secs(120));
        assert_eq!(
            plan.metadata.get("delay_source"),
            Some(&"header".to_string())
        );
    }

    #[test]
    fn plan_extracts_delay_from_body() {
        let mut fixture = ResponseFixture::new(
            "<span class='cf-error-code'>1015</span> Please wait 10 minutes before retrying",
            429,
        );
        fixture.insert_header(SERVER, "cloudflare".parse().unwrap());
        let response = fixture.response();
        let handler = RateLimitHandler::new();
        let plan = handler.plan(&response, None).expect("plan");
        assert!(plan.wait.unwrap() >= Duration::from_secs(600));
        assert_eq!(plan.metadata.get("delay_source"), Some(&"body".to_string()));
    }
}
