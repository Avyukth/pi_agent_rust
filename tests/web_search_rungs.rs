//! Per-rung adapter tests (bd-cv653.2.1): each provider's response parsing is
//! verified against a loopback mock via the base-url override — the unit
//! complement to the full-chain e2e (no binary spawn here; rungs are driven
//! directly). Env mutation is serialized through a shared lock.

mod common;

use common::TestHarness;
use common::harness::MockHttpResponse;
use common::logging::validate_jsonl_v2_only;
use pi::web_search::{RungError, SearchFilters, SearchResult, all_rungs};

fn json_response(status: u16, body: &str) -> MockHttpResponse {
    MockHttpResponse {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.as_bytes().to_vec(),
    }
}

fn html_response(body: &str) -> MockHttpResponse {
    MockHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "text/html".to_string())],
        body: body.as_bytes().to_vec(),
    }
}

const fn filters() -> SearchFilters {
    SearchFilters {
        site: None,
        after: None,
        limit: 10,
    }
}

fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
    &LOCK
}

/// Run one rung directly against the mock with the override map in place
/// (the crate forbids unsafe, so tests never mutate process env; the map is
/// the in-process seam, the env var is the process-level seam).
fn run_rung(
    rung_name: &'static str,
    key: Option<&str>,
    mock_path: &str,
    mock_method: &str,
    mock_response: MockHttpResponse,
    harness: &TestHarness,
) -> Result<Vec<SearchResult>, RungError> {
    let server = harness.start_mock_http_server();
    server.add_route(mock_method, mock_path, mock_response);
    let _guard = env_lock().lock().expect("env lock");
    pi::web_search::set_base_url_override(rung_name, &server.base_url());
    let rungs = all_rungs();
    let rung = &rungs[rung_name];
    let mut result = None;
    asupersync::test_utils::run_test(|| async {
        result = Some(
            (rung.run)(
                &pi::http::client::Client::new(),
                "rust async runtime",
                &filters(),
                key,
            )
            .await,
        );
    });
    pi::web_search::clear_base_url_overrides();
    result.expect("rung future ran to completion")
}

#[test]
fn brave_adapter_parses_results() {
    let harness = TestHarness::new("brave_adapter_parses_results");
    let results = run_rung(
        "brave",
        Some("brave-key"),
        "/res/v1/web/search",
        "GET",
        json_response(200, r#"{"web":{"results":[{"title":"Tokio","url":"https://tokio.rs","description":"runtime"}]}}"#),
        &harness,
    )
    .expect("brave parses");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://tokio.rs");
    assert_eq!(results[0].title, "Tokio");
    assert_eq!(results[0].snippet, "runtime");
    assert_eq!(results[0].source, "brave");
    let path = harness.temp_path("brave_adapter.jsonl");
    harness.write_jsonl_logs(&path).expect("write logs");
    assert!(validate_jsonl_v2_only(&std::fs::read_to_string(&path).expect("read")).is_empty());
}

#[test]
fn tavily_adapter_parses_results() {
    let harness = TestHarness::new("tavily_adapter_parses_results");
    let results = run_rung(
        "tavily",
        Some("tavily-key"),
        "/search",
        "POST",
        json_response(200, r#"{"results":[{"title":"Async Book","url":"https://rust-lang.github.io/async-book/","content":"the official async book"}]}"#),
        &harness,
    )
    .expect("tavily parses");
    assert_eq!(results.len(), 1);
    assert!(results[0].url.contains("async-book"));
    assert_eq!(results[0].snippet, "the official async book");
    assert_eq!(results[0].source, "tavily");
}

#[test]
fn exa_adapter_parses_results() {
    let harness = TestHarness::new("exa_adapter_parses_results");
    let results = run_rung(
        "exa",
        Some("exa-key"),
        "/search",
        "POST",
        json_response(200, r#"{"results":[{"title":"Futures","url":"https://docs.rs/futures","text":"futures crate"}]}"#),
        &harness,
    )
    .expect("exa parses");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, "exa");
    assert_eq!(results[0].snippet, "futures crate");
}

#[test]
fn duckduckgo_adapter_decodes_redirects() {
    let harness = TestHarness::new("duckduckgo_adapter_decodes_redirects");
    let results = run_rung(
        "duckduckgo",
        None,
        "/html/",
        "GET",
        html_response(r#"<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc">Example Doc</a></div>"#),
        &harness,
    )
    .expect("duckduckgo parses");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/doc");
    assert_eq!(results[0].title, "Example Doc");
    assert_eq!(results[0].source, "duckduckgo");
}

#[test]
fn keyed_rung_without_key_is_no_key_error() {
    let harness = TestHarness::new("keyed_rung_without_key_is_no_key_error");
    let _guard = env_lock().lock().expect("env lock");
    // No key argument and (in the sandboxed test process) no env keys: the
    // rung must fail with NoKey BEFORE any network call.
    let rungs = all_rungs();
    let rung = &rungs["tavily"];
    let mut result = None;
    asupersync::test_utils::run_test(|| async {
        result =
            Some((rung.run)(&pi::http::client::Client::new(), "query", &filters(), None).await);
    });
    let result = result.expect("rung future ran to completion");
    let err = result.expect_err("no key must error before any request");
    assert!(err.to_string().contains("no API key"), "error: {err}");
    let path = harness.temp_path("no_key.jsonl");
    harness.write_jsonl_logs(&path).expect("write logs");
    assert!(validate_jsonl_v2_only(&std::fs::read_to_string(&path).expect("read")).is_empty());
}

#[test]
fn rung_429_maps_to_rate_limited() {
    let harness = TestHarness::new("rung_429_maps_to_rate_limited");
    let result = run_rung(
        "tavily",
        Some("k"),
        "/search",
        "POST",
        json_response(429, r#"{"error":"slow"}"#),
        &harness,
    );
    let err = result.expect_err("429 must map to rate limited");
    assert!(err.to_string().contains("rate limited"), "error: {err}");
}

#[test]
fn youcom_adapter_parses_web_section_only() {
    let harness = TestHarness::new("youcom_adapter_parses_web_section_only");
    let results = run_rung(
        "youcom",
        Some("ydc-key"),
        "/v1/search",
        "POST",
        json_response(
            200,
            r#"{"results":{"web":[
                {"url":"https://tokio.rs","title":"Tokio","description":"An async runtime","snippets":["ignored"]},
                {"url":"https://smol.rs","title":"smol","description":"","snippets":["a small async runtime"]},
                {"url":"","title":"no url"}
              ],"news":[{"url":"https://news.example/x","title":"News","description":"not a web hit"}]},
              "metadata":{"search_uuid":"u","query":"rust async runtime","latency":0.1}}"#,
        ),
        &harness,
    )
    .expect("youcom parses");
    assert_eq!(results.len(), 2, "news and url-less hits are skipped");
    assert_eq!(results[0].url, "https://tokio.rs");
    assert_eq!(results[0].title, "Tokio");
    assert_eq!(results[0].snippet, "An async runtime");
    assert_eq!(results[0].source, "youcom");
    assert_eq!(
        results[1].snippet, "a small async runtime",
        "empty description falls back to the first snippet"
    );
}

#[test]
fn youcom_adapter_sends_key_header_and_json_body() {
    let harness = TestHarness::new("youcom_adapter_sends_key_header_and_json_body");
    let server = harness.start_mock_http_server();
    server.add_route(
        "POST",
        "/v1/search",
        json_response(
            200,
            r#"{"results":{"web":[{"url":"https://tokio.rs","title":"Tokio","description":"d"}]}}"#,
        ),
    );
    let _guard = env_lock().lock().expect("env lock");
    pi::web_search::set_base_url_override("youcom", &server.base_url());
    let rungs = all_rungs();
    let rung = &rungs["youcom"];
    let site_filters = SearchFilters {
        site: Some("docs.rs".to_string()),
        after: None,
        limit: 50,
    };
    let mut result = None;
    asupersync::test_utils::run_test(|| async {
        result = Some(
            (rung.run)(
                &pi::http::client::Client::new(),
                "tokio",
                &site_filters,
                Some("ydc-key"),
            )
            .await,
        );
    });
    pi::web_search::clear_base_url_overrides();
    result
        .expect("rung future ran to completion")
        .expect("youcom parses");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-api-key") && value == "ydc-key"),
        "headers: {:?}",
        request.headers
    );
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json body");
    assert_eq!(body["query"], "site:docs.rs tokio");
    assert_eq!(body["count"], 20, "count is capped at 20");
}

#[test]
fn youcom_adapter_without_web_hits_is_parse_error() {
    let harness = TestHarness::new("youcom_adapter_without_web_hits_is_parse_error");
    let result = run_rung(
        "youcom",
        Some("ydc-key"),
        "/v1/search",
        "POST",
        json_response(200, r#"{"results":{"web":[]},"metadata":{}}"#),
        &harness,
    );
    assert!(
        matches!(result, Err(RungError::Parse(_))),
        "empty web section must fall through the chain: {result:?}"
    );
}
