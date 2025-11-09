use super::{CaptchaConfig, CaptchaError, CaptchaProvider, CaptchaResult, CaptchaTask};
use async_trait::async_trait;

/// Placeholder adapter for the CapSolver service.
#[derive(Debug, Clone)]
pub struct CapSolverProvider {
    pub api_key: String,
    pub config: CaptchaConfig,
}

impl CapSolverProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            config: CaptchaConfig::default(),
        }
    }

    pub fn with_config(api_key: impl Into<String>, config: CaptchaConfig) -> Self {
        Self {
            api_key: api_key.into(),
            config,
        }
    }
}

#[async_trait]
impl CaptchaProvider for CapSolverProvider {
    fn name(&self) -> &'static str {
        "capsolver"
    }

    async fn solve(&self, _task: &CaptchaTask) -> CaptchaResult {
        Err(CaptchaError::NotImplemented(self.name()))
    }
}
