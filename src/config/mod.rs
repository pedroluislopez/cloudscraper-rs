//! Settings and configuration module
//!
//! Provides unified configuration with:
//! - Builder pattern
//! - TOML/JSON loading
//! - Feature flags
//! - Granular configuration options

pub mod config;

pub use config::{
    ScraperConfig, ScraperConfigBuilder, ConfigError,
    TimingConfig, TimingProfileType, FeatureFlags, HttpConfig,
};
