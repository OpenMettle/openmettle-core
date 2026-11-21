//! Build the admin route with the same cfg(test)-only DNS and loopback seam as inference.
use openmettle_core::provider_keys;
mod runs {
    pub(super) fn is_canonical_uuid(value: &str) -> bool {
        // The public vocabulary validates its member key with runs::is_canonical_uuid.
        openmettle_core::authz::GrantVocabulary::parse(
            openmettle_core::authz::PROJECT_MEMBER,
            1,
            value,
        )
        .is_ok()
    }
}
#[path = "."]
pub mod provider_http {
    pub use openmettle_core::provider_http::{
        Error, MAX_ADDRESSES, MAX_PRIVATE_RANGES, MAX_TRUST_BUNDLE_BYTES, SETUP_DEADLINE,
        TOTAL_DEADLINE, Trust,
    };
    #[path = "../src/provider_http/gateway.rs"]
    pub mod admin;
    #[path = "provider_http_support/wire.rs"]
    pub(crate) mod fixture;
    #[path = "../src/provider_http/transport.rs"]
    pub mod transport;

    #[test]
    fn generic_endpoint_still_refuses_admin_pagination() {
        let url = "https://gateway.example.test/admin/v1/budgets";
        assert_eq!(transport::endpoint(url).unwrap().url, url);
        assert!(transport::endpoint(&format!("{url}?page=1")).is_err());
    }
}
use admin::{Admin, Create, Resource};
use fixture::{Ca, Reply, Server};
use provider_http::{Error, Trust, admin, fixture};
use provider_keys::gateway::Bearer;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use tokio::time::Instant;
const ADMIN: &[u8] = b"synthetic-admin-for-wire";
const USER: &str = "synthetic-user-for-wire";

fn intent(resource: Resource) -> Create {
    let id = |n| format!("00000000-0000-4000-8000-{n:012}");
    let target = match resource {
        Resource::Principal => 2,
        Resource::Budget => 3,
        Resource::Key => 4,
    };
    Create {
        installation: id(1),
        principal: id(2),
        budget: id(3),
        resource,
        target: id(target),
        operation: id(target + 10),
        revision: 1,
        expected_revision: 0,
    }
}
fn client(s: &Server, ca: &Ca) -> Admin {
    let mut a = Admin::new(
        &format!("https://{}:{}/", fixture::HOST, s.port),
        Trust::Bundle(&ca.pem()),
        &[],
        Bearer::new(ADMIN).unwrap(),
    )
    .unwrap();
    a.fixture(Arc::new(fixture::loopback), true);
    a
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[tokio::test]
async fn committed_creates_with_lost_replies_recover_by_handle() {
    let ca = Ca::new();
    let remote = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    let state = remote.clone();
    let server = Server::start(ca.leaf(fixture::HOST, false), move |req| {
        assert!(
            req.head
                .contains("authorization: Bearer synthetic-admin-for-wire\r\n")
        );
        assert!(!req.head.contains(USER));
        let mut line = req.head.lines().next().unwrap().split_whitespace();
        let method = line.next().unwrap();
        let path = line.next().unwrap();
        if path == "/admin/v1/ready" && method == "GET" {
            return Reply::Bytes(fixture::json(br#"{"ready":true}"#));
        }
        let mut remote = state.lock().unwrap();
        if method == "GET" {
            return match remote.get(path) {
                Some(v) => Reply::Bytes(fixture::json(&serde_json::to_vec(v).unwrap())),
                None => Reply::Bytes(fixture::response(404, &[], b"")),
            };
        }
        assert_eq!(method, "PUT");
        let i: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(
            path,
            format!(
                "/admin/v1/{}s/{}",
                i["resource"].as_str().unwrap(),
                i["target"].as_str().unwrap()
            )
        );
        assert!(req.head.contains(&format!(
            "idempotency-key: {}\r\n",
            i["operation"].as_str().unwrap()
        )));
        assert!(req.head.contains("if-none-match: *\r\n"));
        let bearer = (i["resource"] == "key").then_some(USER);
        assert!(
            remote
                .insert(path.into(), json!({"intent":i,"bearer":bearer}))
                .is_none()
        );
        Reply::Close
    })
    .await;
    let a = client(&server, &ca);
    for resource in [Resource::Principal, Resource::Budget, Resource::Key] {
        let i = intent(resource);
        assert!(matches!(
            a.ensure(&i, deadline()).await,
            Err(admin::Error::Transport(_))
        ));
        let result = a.ensure(&i, deadline()).await.unwrap();
        if resource == Resource::Key {
            let key = result.unwrap();
            assert_eq!(
                key.authorization().as_bytes(),
                format!("Bearer {USER}").as_bytes()
            );
            assert!(key.authorization().is_sensitive());
            assert!(!format!("{key:?}").contains(USER));
        } else {
            assert!(result.is_none());
        }
    }
    assert_eq!(remote.lock().unwrap().len(), 3);
    assert_eq!(server.requests.load(Ordering::SeqCst), 15);
    assert!(!format!("{a:?}").contains("synthetic-admin"));
}

#[tokio::test]
async fn transient_status_defers_beyond_batch_and_permanent_refusal_stops_at_readiness() {
    for (status, retry, seconds) in [
        (408, "0", Some(0)),
        (429, "86400", Some(86400)),
        (429, "86401", None),
        (408, "-1", None),
        (503, "Fri, 01 Jan", None),
        (403, "0", None),
        (401, "0", None),
        (422, "0", None),
        (307, "0", None),
    ] {
        let ca = Ca::new();
        let first = std::sync::atomic::AtomicBool::new(true);
        let server = Server::start(ca.leaf(fixture::HOST, false), move |req| {
            if !first.swap(false, Ordering::SeqCst) {
                assert!(matches!(status, 408 | 429 | 503));
                assert!(req.head.starts_with("GET "));
                if req.head.starts_with("GET /admin/v1/ready ") {
                    return Reply::Bytes(fixture::json(br#"{"ready":true}"#));
                }
                let recovered = json!({"intent":intent(Resource::Key),"bearer":USER});
                return Reply::Bytes(fixture::json(&serde_json::to_vec(&recovered).unwrap()));
            }
            Reply::Bytes(fixture::response(
                status,
                &[
                    ("retry-after", retry),
                    ("location", "https://other.example.test/"),
                ],
                b"discard me",
            ))
        })
        .await;
        let client = client(&server, &ca);
        let i = intent(Resource::Key);
        let err = client.ensure(&i, deadline()).await.unwrap_err();
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        match (status, err) {
            (408 | 429 | 503, admin::Error::Deferred(d)) => {
                if let Some(n) = seconds {
                    assert_eq!(d, Duration::from_secs(n));
                } else {
                    assert!((1000..=2020).contains(&d.as_millis()));
                }
                assert_eq!(
                    client.ensure(&i, Instant::now()).await.unwrap_err(),
                    admin::Error::Transport(Error::Timeout)
                );
                assert_eq!(server.requests.load(Ordering::SeqCst), 1);
                // A later sweep has its own deadline and recovers the original handle.
                let recovered = client.ensure(&i, deadline()).await.unwrap().unwrap();
                assert_eq!(
                    recovered.authorization(),
                    Bearer::new(USER.as_bytes()).unwrap().authorization()
                );
                assert_eq!(server.requests.load(Ordering::SeqCst), 3);
            }
            (401 | 403 | 422, admin::Error::Refused(s)) => assert_eq!(s, status),
            (307, admin::Error::Protocol) => {}
            _ => panic!("unexpected response {err:?}"),
        }
    }
}

#[tokio::test]
async fn tls_and_all_address_checks_precede_admin_bytes() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Close).await;
    let mut a = client(&server, &Ca::new());
    assert!(matches!(
        a.list(Resource::Budget, deadline()).await,
        Err(admin::Error::Transport(Error::Tls))
    ));
    for ip in ["127.0.0.1", "10.0.0.7", "169.254.169.254", "fe80::a"] {
        a.fixture(
            Arc::new(move |_, port| {
                Ok(vec![(ip.parse::<std::net::IpAddr>().unwrap(), port).into()])
            }),
            false,
        );
        assert!(matches!(
            a.list(Resource::Budget, deadline()).await,
            Err(admin::Error::Transport(Error::Address))
        ));
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn readiness_header_and_body_stalls_and_response_ceiling() {
    for (raw, stall) in [
        (b"".as_slice(), true),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{", true),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n", false),
    ] {
        let ca = Ca::new();
        let server = Server::start(ca.leaf(fixture::HOST, false), move |_| {
            Reply::Stall(raw.to_vec())
        })
        .await;
        let a = client(&server, &ca);
        let err = a
            .ensure(
                &intent(Resource::Budget),
                Instant::now() + Duration::from_millis(200),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            admin::Error::Transport(if stall {
                Error::Timeout
            } else {
                Error::TooLarge
            })
        );
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn pagination_has_fixed_origin_page_size_and_page_count() {
    for more_forever in [false, true] {
        let ca = Ca::new();
        let server = Server::start(ca.leaf(fixture::HOST, false), move |req| {
            let path = req.head.lines().next().unwrap();
            let page: u16 = path
                .strip_prefix("GET /admin/v1/keys?page=")
                .unwrap()
                .strip_suffix("&limit=64 HTTP/1.1")
                .unwrap()
                .parse()
                .unwrap();
            let body = json!({
                "ids": [format!("00000000-0000-4000-8000-{page:012}")],
                "more": more_forever || page == 1,
            });
            Reply::Bytes(fixture::json(&serde_json::to_vec(&body).unwrap()))
        })
        .await;
        let res = client(&server, &ca).list(Resource::Key, deadline()).await;
        if more_forever {
            assert_eq!(res.unwrap_err(), admin::Error::Protocol);
        } else {
            assert_eq!(res.unwrap().len(), 2);
        }
        assert_eq!(
            server.requests.load(Ordering::SeqCst),
            if more_forever { 32 } else { 2 }
        );
    }
}

#[tokio::test]
async fn dropping_an_admin_call_closes_its_stalled_connection() {
    use tokio::sync::Notify;
    for mode in 0..3 {
        let ca = Ca::new();
        let server = Server::start(ca.leaf(fixture::HOST, false), move |_| match mode {
            0 => Reply::Gate(Arc::new(Notify::new()), fixture::json(b"{}")),
            1 => Reply::Split(
                b"HTTP/1.1 200 OK\r\n".to_vec(),
                Arc::new(Notify::new()),
                b"content-length: 0\r\n\r\n".to_vec(),
            ),
            _ => Reply::Drip(
                b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n".to_vec(),
                vec![b' '],
            ),
        })
        .await;
        let a = client(&server, &ca);
        let i = intent(Resource::Key);
        {
            let work = a.ensure(&i, deadline());
            tokio::pin!(work);
            tokio::select! { _=server.entered.notified()=>{}, _=&mut work=>panic!("request finished before cancellation")}
        }
        if mode == 2 {
            tokio::time::timeout(Duration::from_secs(2), server.closed.notified())
                .await
                .unwrap();
        }
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }
}
