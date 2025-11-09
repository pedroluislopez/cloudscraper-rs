//! Core utilities shared by challenge detectors, analyzers, and solvers.

pub mod analysis;
pub mod executor;
pub mod reqwest_client;
pub mod timing;
pub mod types;

pub use analysis::{
    ChallengeParseError, IuamChallengeBlueprint, is_cloudflare_response, origin_from_url,
    parse_iuam_challenge,
};
pub use executor::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpClientError, ChallengeHttpResponse,
    OriginalRequest, execute_challenge_submission,
};
pub use reqwest_client::ReqwestChallengeHttpClient;
pub use timing::{DelayStrategy, TimingFeedback};
pub use types::{ChallengeResponse, ChallengeSubmission};
