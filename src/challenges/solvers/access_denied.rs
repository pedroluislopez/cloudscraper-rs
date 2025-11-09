//! Handler for Cloudflare Access Denied (code 1020) responses.
//!
//! Recommends mitigation steps such as proxy rotation and adaptive backoff
//! when Access Denied pages appear instead of solvable forms.

use std::time::Duration;

use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::challenges::core::{ChallengeResponse, is_cloudflare_response};

use super::{ChallengeSolver, MitigationPlan};

const DEFAULT_DELAY_MIN_SECS: f32 = 5.0;
const DEFAULT_DELAY_MAX_SECS: f32 = 15.0;

/// Computes mitigation steps for Access Denied (1020) responses.
pub struct AccessDeniedHandler {
    delay_min: Duration,
    delay_max: Duration,
}

impl AccessDeniedHandler {
    pub fn new() -> Self {
        Self {
            delay_min: Duration::from_secs_f32(DEFAULT_DELAY_MIN_SECS),
            delay_max: Duration::from_secs_f32(DEFAULT_DELAY_MAX_SECS),
        }
    }

    /// Override the random delay range applied before retrying with a new proxy.
    pub fn with_delay_range(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = if max < min { min } else { max };
        self
    }

    /// Returns true if the response matches the Access Denied signature.
    pub fn is_access_denied(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 403
            && ACCESS_DENIED_RE.is_match(response.body)
    }

    /// Build a mitigation plan for Access Denied responses.
    pub fn plan(
        &self,
        response: &ChallengeResponse<'_>,
        proxy_pool: Option<&mut dyn ProxyPool>,
        current_proxy: Option<&str>,
    ) -> Result<MitigationPlan, AccessDeniedError> {
        if !Self::is_access_denied(response) {
            return Err(AccessDeniedError::NotAccessDenied);
        }

        let delay = self.random_delay();
        let mut plan = MitigationPlan::retry_after(delay, "access_denied");
        plan.metadata.insert("trigger".into(), "cf_1020".into());

        match proxy_pool {
            Some(pool) => {
                if let Some(proxy) = current_proxy {
                    pool.report_failure(proxy);
                    plan.metadata
                        .insert("previous_proxy".into(), proxy.to_string());
                }

                if let Some(next_proxy) = pool.next_proxy() {
                    plan = plan.with_proxy(next_proxy.clone());
                    plan.metadata
                        .insert("proxy_rotation".into(), "success".into());
                } else {
                    plan.should_retry = false;
                    plan.reason = "access_denied_no_proxy".into();
                    plan.metadata
                        .insert("proxy_rotation".into(), "unavailable".into());
                }
            }
            None => {
                plan.should_retry = false;
                plan.reason = "access_denied_no_proxy".into();
                plan.metadata
                    .insert("proxy_rotation".into(), "not_configured".into());
            }
        }

        Ok(plan)
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

impl Default for AccessDeniedHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeSolver for AccessDeniedHandler {
    fn name(&self) -> &'static str {
        "access_denied"
    }
}

/// Trait representing a proxy rotation pool.
pub trait ProxyPool {
    fn report_failure(&mut self, proxy: &str);
    fn next_proxy(&mut self) -> Option<String>;
}

#[derive(Debug, Error)]
pub enum AccessDeniedError {
    #[error("response is not a Cloudflare access denied challenge")]
    NotAccessDenied,
}

static ACCESS_DENIED_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r#"(<span[^>]*class=['"]cf-error-code['"]>1020<|Access denied|banned your access)"#,
    )
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .expect("invalid access denied regex")
});

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method, header::SERVER};
    use url::Url;

    struct ResponseFixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
    }

    impl ResponseFixture {
        fn new(body: &str) -> Self {
            let mut headers = HeaderMap::new();
            headers.insert(SERVER, "cloudflare".parse().unwrap());
            Self {
                url: Url::parse("https://example.com/protected").unwrap(),
                headers,
                method: Method::GET,
                body: body.to_string(),
            }
        }

        fn response(&self) -> ChallengeResponse<'_> {
            ChallengeResponse {
                url: &self.url,
                status: 403,
                headers: &self.headers,
                body: &self.body,
                request_method: &self.method,
            }
        }
    }

    struct StubProxyPool {
        proxies: Vec<String>,
        reported: Vec<String>,
    }

    impl StubProxyPool {
        fn new(proxies: &[&str]) -> Self {
            Self {
                proxies: proxies.iter().map(|p| p.to_string()).collect(),
                reported: Vec::new(),
            }
        }
    }

    impl ProxyPool for StubProxyPool {
        fn report_failure(&mut self, proxy: &str) {
            self.reported.push(proxy.to_string());
        }

        fn next_proxy(&mut self) -> Option<String> {
            self.proxies.pop()
        }
    }

    #[test]
    fn detects_access_denied() {
        let fixture = ResponseFixture::new("<span class='cf-error-code'>1020</span> Access denied");
        let response = fixture.response();
        assert!(AccessDeniedHandler::is_access_denied(&response));
    }

    #[test]
    fn plan_rotates_proxy_when_available() {
        let fixture = ResponseFixture::new("<span class='cf-error-code'>1020</span> Access denied");
        let response = fixture.response();
        let mut pool = StubProxyPool::new(&["http://1.1.1.1:8080", "http://2.2.2.2:8080"]);
        let handler = AccessDeniedHandler::new();
        let plan = handler
            .plan(&response, Some(&mut pool), Some("http://1.1.1.1:8080"))
            .expect("plan");
        assert!(plan.should_retry);
        assert!(plan.new_proxy.is_some());
        assert_eq!(
            plan.metadata.get("proxy_rotation"),
            Some(&"success".to_string())
        );
    }

    #[test]
    fn plan_disables_retry_without_proxy_manager() {
        let fixture = ResponseFixture::new("<span class='cf-error-code'>1020</span> Access denied");
        let response = fixture.response();
        let handler = AccessDeniedHandler::new();
        let plan = handler.plan(&response, None, None).expect("plan");
        assert!(!plan.should_retry);
        assert_eq!(
            plan.metadata.get("proxy_rotation"),
            Some(&"not_configured".to_string())
        );
    }
}
