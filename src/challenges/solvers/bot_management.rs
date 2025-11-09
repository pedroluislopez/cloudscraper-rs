//! Handler for Cloudflare Bot Management detections.
//!
//! Triggers advanced evasion tactics such as fingerprint resets and TLS
//! rotation when Bot Management blocks are detected.

use std::time::Duration;

use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::challenges::core::{ChallengeResponse, is_cloudflare_response};

use super::{
    ChallengeSolver, FailureRecorder, FingerprintManager, MitigationPlan, TlsProfileManager,
};

const DEFAULT_DELAY_MIN_SECS: f32 = 30.0;
const DEFAULT_DELAY_MAX_SECS: f32 = 60.0;

/// Plans mitigation steps for Bot Management blocks (1010).
pub struct BotManagementHandler {
    delay_min: Duration,
    delay_max: Duration,
}

impl BotManagementHandler {
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

    pub fn is_bot_management(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 403
            && BOT_MANAGEMENT_RE.is_match(response.body)
    }

    pub fn plan(
        &self,
        response: &ChallengeResponse<'_>,
        fingerprint: Option<&mut dyn FingerprintManager>,
        tls_manager: Option<&mut dyn TlsProfileManager>,
        state_recorder: Option<&dyn FailureRecorder>,
    ) -> Result<MitigationPlan, BotManagementError> {
        if !Self::is_bot_management(response) {
            return Err(BotManagementError::NotBotManagement);
        }

        let domain = response
            .url
            .host_str()
            .ok_or(BotManagementError::MissingHost)?
            .to_string();

        if let Some(recorder) = state_recorder {
            recorder.record_failure(&domain, "cf_bot_management");
        }

        let delay = self.random_delay();
        let mut plan = MitigationPlan::retry_after(delay, "bot_management");
        plan.metadata.insert("trigger".into(), "cf_1010".into());

        if let Some(fingerprint_generator) = fingerprint {
            fingerprint_generator.invalidate(&domain);
            plan.metadata
                .insert("fingerprint_reset".into(), "true".into());
        } else {
            plan.metadata
                .insert("fingerprint_reset".into(), "false".into());
        }

        if let Some(tls) = tls_manager {
            tls.rotate_profile(&domain);
            plan.metadata.insert("tls_rotated".into(), "true".into());
        } else {
            plan.metadata.insert("tls_rotated".into(), "false".into());
        }

        plan.metadata
            .insert("stealth_mode".into(), "enhanced".into());

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

impl Default for BotManagementHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeSolver for BotManagementHandler {
    fn name(&self) -> &'static str {
        "bot_management"
    }
}

#[derive(Debug, Error)]
pub enum BotManagementError {
    #[error("response is not a Cloudflare bot management challenge")]
    NotBotManagement,
    #[error("missing host information on response")]
    MissingHost,
}

static BOT_MANAGEMENT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"(<span[^>]*class=['"]cf-error-code['"]>1010<|Bot management|has banned you temporarily)"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid bot management regex")
});

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method, header::SERVER};
    use std::cell::RefCell;
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
                url: Url::parse("https://example.com/bot-check").unwrap(),
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

        fn domain(&self) -> &str {
            self.url.host_str().unwrap()
        }
    }

    struct StubFingerprint {
        invalidated: Vec<String>,
    }

    impl StubFingerprint {
        fn new() -> Self {
            Self {
                invalidated: Vec::new(),
            }
        }

        fn was_invalidated(&self, domain: &str) -> bool {
            self.invalidated.iter().any(|d| d == domain)
        }
    }

    impl FingerprintManager for StubFingerprint {
        fn invalidate(&mut self, domain: &str) {
            self.invalidated.push(domain.to_string());
        }
    }

    struct StubTlsManager {
        rotated: Vec<String>,
    }

    impl StubTlsManager {
        fn new() -> Self {
            Self {
                rotated: Vec::new(),
            }
        }

        fn was_rotated(&self, domain: &str) -> bool {
            self.rotated.iter().any(|d| d == domain)
        }
    }

    impl TlsProfileManager for StubTlsManager {
        fn rotate_profile(&mut self, domain: &str) {
            self.rotated.push(domain.to_string());
        }
    }

    struct StubRecorder {
        calls: RefCell<Vec<(String, String)>>,
    }

    impl StubRecorder {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }

        fn count(&self) -> usize {
            self.calls.borrow().len()
        }

        fn recorded(&self, domain: &str, reason: &str) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|(d, r)| d == domain && r == reason)
        }
    }

    impl FailureRecorder for StubRecorder {
        fn record_failure(&self, domain: &str, reason: &str) {
            self.calls
                .borrow_mut()
                .push((domain.to_string(), reason.to_string()));
        }
    }

    #[test]
    fn detects_bot_management() {
        let fixture =
            ResponseFixture::new("<span class='cf-error-code'>1010</span> Bot management");
        let response = fixture.response();
        assert!(BotManagementHandler::is_bot_management(&response));
    }

    #[test]
    fn plan_invalidates_fingerprint_and_rotates_tls() {
        let fixture =
            ResponseFixture::new("<span class='cf-error-code'>1010</span> Bot management");
        let response = fixture.response();
        let mut fingerprint = StubFingerprint::new();
        let mut tls = StubTlsManager::new();
        let recorder = StubRecorder::new();
        let handler = BotManagementHandler::new();
        let plan = handler
            .plan(
                &response,
                Some(&mut fingerprint),
                Some(&mut tls),
                Some(&recorder),
            )
            .expect("plan");
        assert!(plan.should_retry);
        assert_eq!(
            plan.metadata.get("fingerprint_reset"),
            Some(&"true".to_string())
        );
        assert_eq!(plan.metadata.get("tls_rotated"), Some(&"true".to_string()));
        assert!(fingerprint.was_invalidated(fixture.domain()));
        assert!(tls.was_rotated(fixture.domain()));
        assert_eq!(recorder.count(), 1);
        assert!(recorder.recorded(fixture.domain(), "cf_bot_management"));
    }

    #[test]
    fn plan_handles_missing_aux_components() {
        let fixture =
            ResponseFixture::new("<span class='cf-error-code'>1010</span> Bot management");
        let response = fixture.response();
        let handler = BotManagementHandler::new();
        let plan = handler.plan(&response, None, None, None).expect("plan");
        assert_eq!(
            plan.metadata.get("fingerprint_reset"),
            Some(&"false".to_string())
        );
        assert_eq!(plan.metadata.get("tls_rotated"), Some(&"false".to_string()));
    }
}
