//! Integration tests for the browser fixture server infrastructure (bd-1xz.1).

#[path = "browser_fixtures/mod.rs"]
mod browser_fixtures;

// Re-export so the #[cfg(test)] modules inside server.rs run as part of this binary.
// The actual tests are defined inside browser_fixtures::server::tests.

#[test]
fn fixture_server_smoke() {
    let server = browser_fixtures::FixtureServer::start().expect("fixture server should start");
    assert!(server.port() > 0, "should bind to a port");
    assert!(server.is_healthy(), "should be healthy after start");
    let url = server.url(browser_fixtures::Fixture::Navigation.path());
    assert!(url.starts_with("http://127.0.0.1:"));
}
