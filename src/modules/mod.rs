//! Cross-cutting services module
//!
//! Augments requests with stealth, metrics, timing, ML, and TLS strategies.
//! All modules support feature gating for lean builds.

pub mod adaptive_timing;
pub mod anti_detection;
pub mod metrics;
pub mod ml;
pub mod performance;
pub mod spoofing;
pub mod tls;
pub mod state;
pub mod events;
pub mod proxy;

// Re-export commonly used types
pub use adaptive_timing::{
    AdaptiveTimingStrategy,
    BehaviorProfile,
    DefaultAdaptiveTiming,
    DomainTimingSnapshot,
    RequestKind,
    TimingOutcome,
    TimingProfile,
    TimingRequest,
};
pub use anti_detection::{
    AntiDetectionConfig,
    AntiDetectionContext,
    AntiDetectionStrategy,
    DefaultAntiDetection,
};
pub use metrics::{DomainStats, GlobalStats, MetricsCollector, MetricsSnapshot};
pub use ml::{FeatureVector, MLConfig, MLOptimizer, StrategyRecommendation};
pub use performance::{PerformanceMonitor, PerformanceConfig, PerformanceReport};
pub use spoofing::{BrowserFingerprint, BrowserType, ConsistencyLevel, FingerprintGenerator};
pub use tls::{BrowserProfile, DefaultTLSManager, TLSConfig};
pub use state::{StateManager, DomainState};
pub use events::{
    EventDispatcher, EventHandler, ScraperEvent, PreRequestEvent, PostResponseEvent,
    ChallengeEvent, ErrorEvent, RetryEvent, LoggingHandler, MetricsHandler,
};
pub use proxy::{ProxyConfig, ProxyHealthReport, ProxyManager, RotationStrategy};



