//! Solver for Cloudflare IUAM / JavaScript challenge v1.
//!
//! Parses the challenge page, evaluates the embedded JavaScript snippet via the
//! provided interpreter, and produces the submission payload the caller must
//! POST back to Cloudflare.

use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpResponse, ChallengeParseError,
    ChallengeResponse, ChallengeSubmission, OriginalRequest, execute_challenge_submission,
    is_cloudflare_response, origin_from_url, parse_iuam_challenge,
};
use crate::external_deps::interpreters::{InterpreterError, JavascriptInterpreter};

use super::ChallengeSolver;

/// Solver for IUAM (v1) challenges.
pub struct JavascriptV1Solver {
    interpreter: Arc<dyn JavascriptInterpreter>,
}

impl JavascriptV1Solver {
    pub fn new(interpreter: Arc<dyn JavascriptInterpreter>) -> Self {
        Self { interpreter }
    }

    /// Returns `true` if the response resembles a Cloudflare IUAM challenge.
    pub fn is_iuam_challenge(&self, response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && matches!(response.status, 429 | 503)
            && response.body.contains("/cdn-cgi/images/trace/jsch/")
            && parse_iuam_challenge(response).is_ok()
    }

    /// Returns `true` if Cloudflare responded with a captcha challenge.
    pub fn is_captcha_challenge(&self, response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 403
            && response.body.contains("__cf_chl_captcha_tk__")
            && response.body.contains("data-sitekey")
    }

    /// Returns `true` when Cloudflare blocked the request (1020 firewall).
    pub fn is_firewall_blocked(&self, response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 403
            && response
                .body
                .to_ascii_lowercase()
                .contains("<span class=\"cf-error-code\">1020</span>")
    }

    /// Parse the IUAM page and return the ready-to-submit payload.
    pub fn solve(
        &self,
        response: &ChallengeResponse<'_>,
    ) -> Result<ChallengeSubmission, JavascriptV1Error> {
        if !self.is_iuam_challenge(response) {
            return Err(JavascriptV1Error::NotAnIuamChallenge);
        }

        let base_url = response.url.clone();
        let host = base_url.host_str().ok_or(JavascriptV1Error::MissingHost)?;

        let blueprint = parse_iuam_challenge(response).map_err(JavascriptV1Error::Parse)?;

        let answer = self
            .interpreter
            .solve_challenge(response.body, host)
            .map_err(JavascriptV1Error::Interpreter)?;

        let mut submission = blueprint
            .to_submission(&base_url, vec![("jschl_answer".to_string(), answer)])
            .map_err(JavascriptV1Error::Parse)?;

        submission.wait = extract_delay(response.body)?;
        submission
            .headers
            .insert("Referer".into(), response.url.as_str().to_string());
        submission
            .headers
            .insert("Origin".into(), origin_from_url(&base_url));

        Ok(submission)
    }

    /// Solve the challenge and immediately submit the response through the provided client.
    pub async fn solve_and_submit(
        &self,
        client: Arc<dyn ChallengeHttpClient>,
        response: &ChallengeResponse<'_>,
        original_request: OriginalRequest,
    ) -> Result<ChallengeHttpResponse, JavascriptV1Error> {
        let submission = self.solve(response)?;
        execute_challenge_submission(client, submission, original_request)
            .await
            .map_err(JavascriptV1Error::Submission)
    }
}

impl ChallengeSolver for JavascriptV1Solver {
    fn name(&self) -> &'static str {
        "javascript_v1"
    }
}

fn extract_delay(body: &str) -> Result<Duration, JavascriptV1Error> {
    static DELAY_RE: Lazy<Regex> = Lazy::new(|| {
        RegexBuilder::new(r#"submit\(\);\r?\n\s*},\s*([0-9]+)"#)
            .case_insensitive(true)
            .build()
            .unwrap()
    });

    let captures = DELAY_RE
        .captures(body)
        .ok_or(JavascriptV1Error::DelayNotFound)?;

    let millis = captures
        .get(1)
        .and_then(|m| m.as_str().parse::<u64>().ok())
        .ok_or(JavascriptV1Error::DelayNotFound)?;

    Ok(Duration::from_millis(millis))
}

/// IUAM solver errors.
#[derive(Debug, Error)]
pub enum JavascriptV1Error {
    #[error("response is not an IUAM challenge")]
    NotAnIuamChallenge,
    #[error("unable to determine challenge host")]
    MissingHost,
    #[error("missing Cloudflare delay value")]
    DelayNotFound,
    #[error("javascript interpreter error: {0}")]
    Interpreter(InterpreterError),
    #[error("challenge parsing error: {0}")]
    Parse(ChallengeParseError),
    #[error("challenge submission failed: {0}")]
    Submission(ChallengeExecutionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenges::core::ChallengeHttpClientError;
    use async_trait::async_trait;
    use http::{HeaderMap, Method, header::SERVER};
    use std::sync::Mutex;
    use url::Url;

    struct StubInterpreter;

    impl JavascriptInterpreter for StubInterpreter {
        fn solve_challenge(
            &self,
            _page_html: &str,
            _host: &str,
        ) -> Result<String, InterpreterError> {
            Ok("42".into())
        }
    }

    struct ResponseFixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
        status: u16,
    }

    impl ResponseFixture {
        fn new(body: &str, status: u16) -> Self {
            let mut headers = HeaderMap::new();
            headers.insert(SERVER, "cloudflare".parse().unwrap());
            Self {
                url: Url::parse("https://example.com/").unwrap(),
                headers,
                method: Method::GET,
                body: body.to_string(),
                status,
            }
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

        fn url(&self) -> &Url {
            &self.url
        }
    }

    #[test]
    fn solve_extracts_payload() {
        let html = r#"
            <html>
              <body>
                <form id='challenge-form' action='/cdn-cgi/l/chk_jschl?__cf_chl_f_tk=foo' method='POST'>
                  <input type='hidden' name='r' value='abc'/>
                  <input type='hidden' name='jschl_vc' value='def'/>
                  <input type='hidden' name='pass' value='ghi'/>
                </form>
                <script>setTimeout(function(){ submit();
                }, 4000);</script>
                <script src='/cdn-cgi/images/trace/jsch/'></script>
              </body>
            </html>
        "#;

        let solver = JavascriptV1Solver::new(Arc::new(StubInterpreter));
        let fixture = ResponseFixture::new(html, 503);
        let resp = fixture.response();
        assert!(solver.is_iuam_challenge(&resp));
        let submission = solver.solve(&resp).unwrap();
        assert_eq!(submission.method, Method::POST);
        assert_eq!(
            submission.form_fields.get("jschl_answer"),
            Some(&"42".to_string())
        );
        assert_eq!(submission.wait, Duration::from_millis(4000));
    }

    struct StubClient {
        responses: Mutex<Vec<ChallengeHttpResponse>>,
    }

    impl StubClient {
        fn new(responses: Vec<ChallengeHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().rev().collect()),
            }
        }

        fn pop_response(&self) -> ChallengeHttpResponse {
            self.responses
                .lock()
                .unwrap()
                .pop()
                .expect("no more stub responses")
        }
    }

    #[async_trait]
    impl ChallengeHttpClient for StubClient {
        async fn send_form(
            &self,
            _method: &Method,
            _url: &Url,
            _headers: &http::HeaderMap,
            _form_fields: &std::collections::HashMap<String, String>,
            _allow_redirects: bool,
        ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
            Ok(self.pop_response())
        }

        async fn send_with_body(
            &self,
            _method: &Method,
            _url: &Url,
            _headers: &http::HeaderMap,
            _body: Option<&[u8]>,
            _allow_redirects: bool,
        ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
            Ok(self.pop_response())
        }
    }

    #[tokio::test]
    async fn solve_and_submit_executes_challenge() {
        let solver = JavascriptV1Solver::new(Arc::new(StubInterpreter));
        let html = r#"
            <html>
              <body>
                <form id='challenge-form' action='/cdn-cgi/l/chk_jschl?__cf_chl_f_tk=foo' method='POST'>
                  <input type='hidden' name='r' value='abc'/>
                  <input type='hidden' name='jschl_vc' value='def'/>
                  <input type='hidden' name='pass' value='ghi'/>
                </form>
                <script>setTimeout(function(){ submit();
                }, 0);</script>
                <script src='/cdn-cgi/images/trace/jsch/'></script>
              </body>
            </html>
        "#;
        let fixture = ResponseFixture::new(html, 503);
        let response = fixture.response();
        let original = OriginalRequest::new(Method::GET, fixture.url().clone());

        let client = Arc::new(StubClient::new(vec![ChallengeHttpResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: Vec::new(),
            url: Url::parse("https://example.com/success").unwrap(),
            is_redirect: false,
        }]));

        let result = solver
            .solve_and_submit(client, &response, original)
            .await
            .unwrap();

        assert_eq!(result.status, 200);
    }
}
