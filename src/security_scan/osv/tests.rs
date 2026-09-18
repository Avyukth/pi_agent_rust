use super::*;
use super::super::dependencies::{Excluded, Location};

fn inventory(count: usize) -> Inventory {
    Inventory {
        schema:super::super::dependencies::INVENTORY_SCHEMA.into(), scope:"test lockfiles".into(),
        lockfiles:vec![], excluded:vec![Excluded {
            location:Location { lockfile:"private/workspace/Cargo.lock".into(), package_path:None },
            reason:"local_or_workspace_package".into(),
        }],
        packages:(0..count).map(|index| Package {
            ecosystem:"crates.io".into(), name:format!("package-{index}"), version:"1.2.3".into(),
            locations:vec![Location { lockfile:"private/workspace/Cargo.lock".into(), package_path:None }],
        }).collect(),
    }
}
fn advisory(id: &str) -> Value { json!({"id":id,"modified":"2026-01-01T00:00:00Z"}) }
fn work(index: usize) -> Work { Work { index, token:None } }

#[test]
fn only_public_package_coordinates_and_query_tokens_leave_inventory() {
    let inventory = inventory(1);
    let request = Work { index:0, token:Some("page-A".into()) }.query(&inventory.packages[0]);
    assert_eq!(request, json!({"package":{"ecosystem":"crates.io","name":"package-0"},"version":"1.2.3","page_token":"page-A"}));
    assert!(!request.to_string().contains("private"));
    assert!(request.get("locations").is_none());
}

#[test]
fn independent_page_tokens_preserve_original_package_indices() {
    let mut report = Report::new(inventory(3));
    let pending = report.apply_pages(&[work(0),work(1),work(2)], &json!({"results":[
        {"vulns":[advisory("GHSA-a")],"next_page_token":"first"},
        {},
        {"next_page_token":"third"}
    ]})).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].index, 0);
    assert_eq!(pending[1].index, 2);
    assert!(report.queries[1].complete);
    assert!(!report.queries[0].complete && !report.queries[2].complete);
    let next = report.apply_pages(&pending, &json!({"results":[{}, {"vulns":[advisory("GHSA-z")]}]})).unwrap();
    assert!(next.is_empty());
    assert!(report.queries.iter().all(|query|query.complete));
    assert!(report.queries[2].advisories.contains_key("GHSA-z"));
    assert_eq!(report.matches().count(), 2);
}

#[test]
fn empty_page_with_token_is_not_an_empty_completed_query() {
    let mut report = Report::new(inventory(1));
    let pending = report.apply_pages(&[work(0)], &json!({"results":[{"next_page_token":"another"}]})).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(!report.queries[0].complete);
    assert!(report.output().unwrap().is_error);
    assert_eq!(report.output().unwrap().details.unwrap()["status"], "incomplete");
}

#[test]
fn malformed_or_short_batch_is_atomic_and_never_certifies_clean() {
    for response in [
        json!({"results":[{}]}),
        json!({"results":[{}, {"vulns":null}]}),
        json!({"results":[{}, {"vulns":[{"id":"GHSA-a"}]}]}),
        json!({"results":[{}, {"error":"failure"}]}),
        json!({"results":[{}, {"next_page_token":7}]}),
    ] {
        let mut report = Report::new(inventory(2));
        assert!(report.apply_pages(&[work(0),work(1)], &response).is_err());
        assert!(report.queries.iter().all(|query|!query.complete && query.pages == 0));
        assert!(report.output().unwrap().is_error);
    }
}

#[test]
fn cyclic_or_exhausted_pagination_is_explicit_incompleteness() {
    let mut report = Report::new(inventory(1));
    let pending = report.apply_pages(&[work(0)], &json!({"results":[{"next_page_token":"repeat"}]})).unwrap();
    assert!(report.apply_pages(&pending, &json!({"results":[{"next_page_token":"repeat"}]})).is_err());
    assert_eq!(report.queries[0].pages, 1);
    report.queries[0].pages = MAX_PAGES;
    assert!(report.apply_pages(&pending, &json!({"results":[{}]})).is_err());
    assert!(!report.queries[0].complete);
}

#[test]
fn duplicate_advisories_do_not_duplicate_matches_and_budget_failures_are_atomic() {
    let mut report = Report::new(inventory(2));
    let pending = report.apply_pages(&[work(0)], &json!({"results":[{"vulns":[advisory("GHSA-a"),advisory("GHSA-a")],"next_page_token":"next"}]})).unwrap();
    report.apply_pages(&pending, &json!({"results":[{"vulns":[advisory("GHSA-a")]}]})).unwrap();
    assert_eq!(report.matches().count(), 1);
    let many: Vec<_> = (0..MAX_MATCHES).map(|index|advisory(&format!("GHSA-{index}"))).collect();
    assert!(report.apply_pages(&[work(1)], &json!({"results":[{"vulns":many}]})).is_err());
    assert!(!report.queries[1].complete);
    assert_eq!(report.matches().count(), 1);
}

#[test]
fn detail_fixes_are_package_specific_and_never_git_hash_upgrades() {
    let detail = Detail::parse("GHSA-a", &json!({"id":"GHSA-a","summary":"Problem\nsummary",
        "aliases":["CVE-2026-1234"],"withdrawn":"2026-01-02T00:00:00Z",
        "affected":[
            {"package":{"ecosystem":"crates.io","name":"package-0"},"ranges":[
                {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.4"}]},
                {"type":"GIT","events":[{"fixed":"9.9.9"}]}
            ]},
            {"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"3.0.0"}]}]}
        ]})).unwrap();
    assert!(detail.withdrawn);
    assert!(!detail.summary.contains('\n'));
    assert_eq!(detail.fixed[&("crates.io".into(),"package-0".into())], BTreeSet::from(["1.2.4".into()]));
    assert!(Detail::parse("GHSA-a", &json!({"id":"GHSA-b"})).is_err());
    assert!(Detail::parse("GHSA-a", &json!({"id":"GHSA-a","withdrawn":true})).is_err());
}

#[test]
fn complete_queries_with_missing_metadata_keep_the_matches_visible() {
    let mut report = Report::new(inventory(1));
    report.apply_pages(&[work(0)], &json!({"results":[{"vulns":[advisory("GHSA-a")]}]})).unwrap();
    report.query_complete = true;
    let output = report.output().unwrap();
    assert!(!output.is_error);
    let details = output.details.unwrap();
    assert_eq!(details["status"], "complete_with_metadata_gaps");
    assert_eq!(details["advisoryMatches"], 1);
    assert_eq!(details["findings"][0]["metadataAvailable"], false);
    assert_eq!(report.sarif()["runs"][0]["invocations"][0]["executionSuccessful"], true);
}

#[test]
fn no_eligible_packages_is_not_checked_and_is_not_clean() {
    let report = Report::new(inventory(0));
    assert_eq!(report.status(), "not_checked");
    assert!(report.output().unwrap().is_error);
    assert_eq!(report.sarif()["runs"][0]["invocations"][0]["executionSuccessful"], false);
}

#[test]
fn expired_query_deadline_fails_before_any_native_http_dispatch() {
    let client = Client::default().with_base("http://127.0.0.1:1/").unwrap();
    let owner = AgentCx::for_current_or_request();
    let result = futures::executor::block_on(client.exchange(&owner,"v1/querybatch",Some(&json!({"queries":[]})),Instant::now()));
    assert_eq!(result.unwrap_err().code,"OSV_TIMEOUT");
}

#[test]
fn dependency_fingerprints_ignore_location_but_separate_versions_and_advisories() {
    let mut package = inventory(1).packages.remove(0);
    let first = finding_id(&package,"GHSA-a");
    package.locations.clear();
    assert_eq!(finding_id(&package,"GHSA-a"), first);
    assert_ne!(finding_id(&package,"GHSA-b"), first);
    package.version = "2.0.0".into();
    assert_ne!(finding_id(&package,"GHSA-a"), first);
    assert_eq!(first.len(), 64);
    assert_eq!(relative_uri("packages/a b/Cargo.lock"), "packages/a%20b/Cargo.lock");
}

#[test]
fn only_trusted_https_or_literal_loopback_endpoints_are_accepted() {
    for base in ["https://api.osv.dev/", "http://127.0.0.1:1234/fixture", "http://[::1]:1234/"] {
        assert!(Client::default().with_base(base).is_ok(), "{base}");
    }
    for base in ["file:///etc/passwd", "http://example.com/", "https://user:secret@example.com/", "https://example.com/?token=x", "http://localhost:1234/"] {
        assert!(Client::default().with_base(base).is_err(), "{base}");
    }
    for id in ["../secret", ".", "..", "evil?x=1", "bad\nheader"] { assert!(!valid_id(id)); }
}

#[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
mod wire {
    use super::*;
    use crate::security_scan::SecurityScanTool;
    use crate::tools::Tool as _;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;

    fn runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::new().enable_parking(false)
            .worker_threads(2).blocking_threads(1,8).build().expect("runtime")
    }
    fn cargo_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"),
            "version = 4\n[[package]]\nname='public-crate'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='private-workspace-name'\nversion='1.0.0'\n").unwrap();
        dir
    }
    fn read_request(socket: &mut TcpStream) -> (String, Value) {
        socket.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut bytes = Vec::new();
        loop {
            if let Some(end) = bytes.windows(4).position(|part|part == b"\r\n\r\n") {
                let end = end + 4;
                let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                let length = headers.lines().filter_map(|line|line.split_once(':'))
                    .find(|(name,_)|name.eq_ignore_ascii_case("content-length"))
                    .map_or(0,|(_,value)|value.trim().parse::<usize>().unwrap());
                assert!(length < 1024 * 1024);
                if bytes.len() >= end + length {
                    let body = if length == 0 { Value::Null } else { serde_json::from_slice(&bytes[end..end+length]).unwrap() };
                    return (headers, body);
                }
            }
            assert!(Instant::now() < deadline, "fixture request exceeded total deadline");
            let mut chunk = [0_u8;4096];
            match socket.read(&mut chunk) {
                Ok(0) => panic!("unexpected request EOF"),
                Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                Err(error) if matches!(error.kind(),std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                Err(error) => panic!("fixture request failed: {error}"),
            }
            assert!(bytes.len() < 1024 * 1024);
        }
    }
    fn peer(responses: Vec<(u16,Value)>) -> (String,thread::JoinHandle<Vec<(String,Value)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/",listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let mut captured = Vec::new();
            for (status,body) in responses {
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket,_)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline,"fixture client did not connect");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                captured.push(read_request(&mut socket));
                let body = serde_json::to_vec(&body).unwrap();
                write!(socket,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                socket.write_all(&body).unwrap();
            }
            captured
        });
        (base,worker)
    }

    #[test]
    fn native_http_audit_paginates_hydrates_and_exports_actual_results() {
        let dir = cargo_workspace();
        let (base,server) = peer(vec![
            (200,json!({"results":[{"next_page_token":"continue-this-package"}]})),
            (200,json!({"results":[{"vulns":[advisory("GHSA-fixture")]}]})),
            (200,json!({"id":"GHSA-fixture","summary":"Fixture advisory","aliases":["CVE-2026-1234"],
                "affected":[{"package":{"ecosystem":"crates.io","name":"public-crate"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]})),
        ]);
        let tool = SecurityScanTool::new(dir.path()).with_osv_base_url(&base).unwrap();
        let output = runtime().block_on(tool.execute("audit",json!({"op":"audit_dependencies","sarifOut":"audit.sarif"}),None)).unwrap();
        assert!(!output.is_error);
        let details = output.details.unwrap();
        assert_eq!(details["status"],"complete");
        assert_eq!(details["eligiblePackages"],1);
        assert_eq!(details["excludedEntries"],1);
        assert_eq!(details["findings"][0]["advisoryId"],"GHSA-fixture");
        assert_eq!(details["findings"][0]["fixedVersionBoundaries"],json!(["1.0.1"]));
        let captured = server.join().unwrap();
        assert_eq!(captured.len(),3);
        assert!(captured[0].0.starts_with("POST /v1/querybatch "));
        assert_eq!(captured[0].1["queries"][0],json!({"package":{"ecosystem":"crates.io","name":"public-crate"},"version":"1.0.0"}));
        assert_eq!(captured[1].1["queries"][0]["page_token"],"continue-this-package");
        assert!(captured[2].0.starts_with("GET /v1/vulns/GHSA-fixture "));
        for (headers,body) in captured {
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
            assert!(!body.to_string().contains("private-workspace-name"));
            assert!(!body.to_string().contains("Cargo.lock"));
        }
        let sarif: Value = serde_json::from_slice(&std::fs::read(dir.path().join("audit.sarif")).unwrap()).unwrap();
        assert_eq!(sarif["version"],"2.1.0");
        assert_eq!(sarif["runs"][0]["invocations"][0]["executionSuccessful"],true);
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(),1);
        assert_eq!(sarif["runs"][0]["properties"]["inventory"]["lockfiles"][0]["path"],"Cargo.lock");
    }

    #[test]
    fn native_http_outage_and_uncorrelated_response_are_incomplete_not_clean() {
        for (status,body,code) in [
            (503,json!({"error":"unavailable"}),"OSV_HTTP"),
            (200,json!({"results":[]}),"OSV_PROTOCOL"),
        ] {
            let dir = cargo_workspace();
            let (base,server) = peer(vec![(status,body)]);
            let tool = SecurityScanTool::new(dir.path()).with_osv_base_url(&base).unwrap();
            let output = runtime().block_on(tool.execute("audit",json!({"op":"audit_dependencies"}),None)).unwrap();
            assert!(output.is_error);
            let details = output.details.unwrap();
            assert_eq!(details["queryComplete"],false);
            assert_eq!(details["completedQueries"],0);
            assert_eq!(details["failures"][0]["code"],code);
            assert_eq!(server.join().unwrap().len(),1,"no automatic retries");
        }
    }

    #[test]
    fn missing_metadata_never_erases_successfully_matched_advisories() {
        let dir = cargo_workspace();
        let (base,server) = peer(vec![
            (200,json!({"results":[{"vulns":[advisory("GHSA-fixture")]}]})),
            (503,json!({"error":"no details"})),
        ]);
        let tool = SecurityScanTool::new(dir.path()).with_osv_base_url(&base).unwrap();
        let output = runtime().block_on(tool.execute("audit",json!({"op":"audit_dependencies"}),None)).unwrap();
        let details = output.details.unwrap();
        assert_eq!(details["queryComplete"],true);
        assert_eq!(details["metadataComplete"],false);
        assert_eq!(details["advisoryMatches"],1);
        assert_eq!(details["findings"][0]["advisoryId"],"GHSA-fixture");
        assert_eq!(server.join().unwrap().len(),2);
    }
}
