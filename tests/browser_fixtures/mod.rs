//! Shared browser test fixtures for Pi Chrome E2E, soak, and Chrome bump tests.
//!
//! Provides:
//! - `FixtureServer`: minimal HTTP server serving deterministic test pages
//! - Named fixture scenarios for stable, reusable test URLs
//! - CI-safe random port allocation with graceful shutdown
//!
//! # Fixture Scenarios
//!
//! | Scenario | URL Path | Purpose |
//! |----------|----------|---------|
//! | navigation | `/navigation.html` | Back/forward/reload, pushState, link clicks |
//! | form | `/form.html` | Text inputs, select, checkbox, radio, file upload |
//! | console_errors | `/console_errors.html` | Console error/warn observation pipeline |
//! | network_failure | `/network_failure.html` | Fetch success/404/500/timeout/CORS |
//! | hot_reload | `/hot_reload.html` | DOM mutation, SSE updates, dynamic elements |
//!
//! # Usage
//!
//! ```rust,no_run
//! use browser_fixtures::FixtureServer;
//!
//! let server = FixtureServer::start().expect("fixture server");
//! let url = server.url("/navigation.html");
//! // ... drive browser to url ...
//! drop(server); // graceful shutdown
//! ```

pub mod server;

pub use server::FixtureServer;

/// Named fixture scenarios with their URL paths and descriptions.
#[derive(Debug, Clone, Copy)]
pub enum Fixture {
    /// Navigation: back/forward/reload, pushState, link navigation.
    Navigation,
    /// Form: text, email, password, textarea, select, checkbox, radio, file.
    Form,
    /// Console errors: triggered errors/warnings for observation testing.
    ConsoleErrors,
    /// Network failure: fetch OK, 404, 500, timeout, CORS errors.
    NetworkFailure,
    /// Hot reload: SSE updates, DOM mutations, dynamic element creation.
    HotReload,
}

impl Fixture {
    /// URL path for this fixture (relative to server root).
    pub fn path(self) -> &'static str {
        match self {
            Self::Navigation => "/navigation.html",
            Self::Form => "/form.html",
            Self::ConsoleErrors => "/console_errors.html",
            Self::NetworkFailure => "/network_failure.html",
            Self::HotReload => "/hot_reload.html",
        }
    }

    /// Human-readable scenario name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Navigation => "navigation",
            Self::Form => "form",
            Self::ConsoleErrors => "console_errors",
            Self::NetworkFailure => "network_failure",
            Self::HotReload => "hot_reload",
        }
    }

    /// All available fixtures.
    pub fn all() -> &'static [Fixture] {
        &[
            Self::Navigation,
            Self::Form,
            Self::ConsoleErrors,
            Self::NetworkFailure,
            Self::HotReload,
        ]
    }
}
