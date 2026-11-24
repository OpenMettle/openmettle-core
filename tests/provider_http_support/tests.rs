//! Token transport evidence (ADR 0010). Synthetic hosts, in-memory PKI, loopback only.
use super::fixture::{self, Ca, Reply, Server};
use super::*;
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn address_policy_boundaries() {
    for denied in [
        "0.0.0.0",
        "0.255.255.255",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.0.0",
        "169.254.169.254",
        "169.254.255.255",
        "192.0.0.8",
        "192.0.0.170",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.175.48.1",
        "198.18.0.0",
        "198.19.255.255",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "168.63.129.16",
        // Private, CGNAT and ULA require an explicit allowlist.
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "100.100.100.200",
        "fc00::1",
        "fdff:ffff::1",
        "fd00:ec2::254",
        // IPv6 special, embedded-IPv4 and transition forms are refused, not decoded.
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "::8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:0:4136:e378::1",
        "2001:1ff:ffff::1",
        "2001:2::1",
        "2001:db8::1",
        "2002:808:808::1",
        "2002:a9fe:a9fe::1",
        "2620:4f:8000::1",
        "3fff::1",
        "5f00::1",
        "fe80::1",
        "ff02::1",
        // Unallocated global unicast and space outside 2000::/3.
        "3ffe::1",
        "2004::1",
        "4000::1",
        "1fff:ffff::1",
    ] {
        assert!(!permitted(ip(denied), &[]), "{denied}");
    }
    for public in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "169.253.255.255",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.255",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "2001:200::1",
        "2001:4860:4860::8888",
        "2606:4700::1111",
        "2620:4f:7fff::1",
        "2a00:1450::1",
        "2800::1",
        "2c0f::1",
    ] {
        assert!(permitted(ip(public), &[]), "{public}");
    }
}

#[test]
fn private_ranges_are_explicit_bounded_subnets_and_hard_denies_win() {
    let allowed = [
        "10.20.0.0/24",
        "fd12:3456::/32",
        "100.64.0.0/10",
        "fd00::/8",
    ]
    .iter()
    .map(|r| private_range(r).unwrap())
    .collect::<Vec<_>>();
    for yes in [
        "10.20.0.0",
        "10.20.0.255",
        "fd12:3456::1",
        "100.100.100.199",
    ] {
        assert!(permitted(ip(yes), &allowed), "{yes}");
    }
    for no in [
        "10.20.1.0",
        "10.19.255.255",
        "172.16.0.1",
        "fc12:3456::1",
        "100.100.100.200",
        "fd00:ec2::254",
        "127.0.0.1",
        "169.254.169.254",
    ] {
        assert!(!permitted(ip(no), &allowed), "{no}");
    }
    for bad in [
        "10.0.0.0/7",
        "11.0.0.0/8",
        "10.0.0.1/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "8.8.8.0/24",
        "fe80::/10",
        "fc00::/6",
        "2001:db8::/32",
        "10.0.0.0/33",
        "10.0.0.0/",
        "10.0.0.0",
        "010.0.0.0/8",
        "10.0.0.0/08",
        "FC00::/7",
        "fc00:0::/7",
        " 10.0.0.0/8",
    ] {
        assert!(private_range(bad).is_err(), "{bad}");
    }
    let many = vec!["10.0.0.0/8"; MAX_PRIVATE_RANGES + 1];
    let ca = Ca::new();
    assert_eq!(
        ProviderTransport::new(&fixture::url(8443), Trust::Bundle(&ca.pem()), &many).unwrap_err(),
        Error::Configuration
    );
    assert!(
        ProviderTransport::new(
            &fixture::url(8443),
            Trust::Bundle(&ca.pem()),
            &many[..MAX_PRIVATE_RANGES]
        )
        .is_ok()
    );
}

#[test]
fn endpoints_are_canonical_https_dns_names_only() {
    for good in [
        "https://provider.example.test/token",
        "https://provider.example.test:8443/realms/a-b/protocol/openid-connect/token",
    ] {
        assert!(endpoint(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "http://provider.example.test/token",
        "https://127.0.0.1/token",
        "https://[::1]/token",
        "https://0x7f.1/token",
        "https://2130706433/token",
        "https://user@provider.example.test/token",
        "https://provider.example.test/token?x=1",
        "https://provider.example.test/token#f",
        "https://provider.example.test:443/token",
        "https://Provider.example.test/token",
        "https://provider.example.test./token",
        "https://provider..example.test/token",
        "https://provider.example.test/a/../token",
        "https://provider.example.test/to%6Ben",
        "https://provider.example.test/to ken",
        "https://provider.example.test/to\\ken",
        "https://localhost/token",
        "https://provider.example.test",
        "https://provider_x.example.test/token",
        "https://xn--nxasmq6b.example.test:99999/token",
    ] {
        assert!(endpoint(bad).is_err(), "{bad}");
    }
}

/// Plain HTTP is an option of the metered gateway route alone (ADR 0044). Every other client
/// built on the transport core keeps `https://`; the OTLP exporter's refusal is in its own
/// tests, and it cannot reach the gateway route's parser, which is private to `provider_http`.
#[test]
fn only_the_metered_gateway_route_accepts_plain_http() {
    use crate::provider_http::{
        gateway::Admin,
        inference::{Gateway, Protocol, Qualification, Timeouts},
    };
    let ca = Ca::new();
    let pem = ca.pem();
    let plain = "http://gateway.example.test:8082/v1/chat/completions";
    let secure = "https://gateway.example.test/v1/chat/completions";
    let catalog = crate::model_config::Catalog::load(include_bytes!(
        "../fixtures/conversation-catalog-v1.json"
    ))
    .unwrap();
    let qualification = || Qualification {
        model: "a".into(),
        pin: catalog.model("a").unwrap().pin.clone(),
        protocol: Protocol::Chat,
        json: true,
        sse: false,
        functions: None,
        images: false,
        parallel: false,
        usage: true,
        tool_separator_whitespace: false,
    };
    let timeouts = Timeouts {
        setup: Duration::from_secs(1),
        idle: Duration::from_secs(1),
        overall: Duration::from_secs(1),
    };

    assert!(endpoint(plain).is_err());
    assert!(ProviderTransport::new(plain, Trust::Bundle(&pem), &[]).is_err());
    let token = ProviderTransport::new(&fixture::url(8443), Trust::Bundle(&pem), &[]).unwrap();
    let document = "http://provider.example.test/.well-known/openid-configuration";
    assert!(ProviderDocuments::configured(&token, document, &fixture::url(8443)).is_err());
    assert!(ProviderDocuments::configured(&token, &fixture::url(8443), document).is_err());
    let admin = || crate::provider_keys::gateway::Bearer::new(b"synthetic-admin").unwrap();
    assert!(
        Admin::new(
            "http://gateway.example.test/",
            Trust::Bundle(&pem),
            &[],
            admin()
        )
        .is_err()
    );
    assert!(
        Admin::new(
            "https://gateway.example.test/",
            Trust::Bundle(&pem),
            &[],
            admin()
        )
        .is_ok()
    );
    assert!(Gateway::new(plain, Trust::Bundle(&pem), &[], qualification(), timeouts).is_err());
    assert!(Gateway::new(secure, Trust::Bundle(&pem), &[], qualification(), timeouts).is_ok());

    assert!(!transport::gateway_endpoint(plain).unwrap().tls());
    assert!(transport::gateway_endpoint(secure).unwrap().tls());
    for bad in [
        "http://gateway.example.test:80/v1/chat/completions",
        "http://10.0.0.1/v1/chat/completions",
        "http://localhost/v1/chat/completions",
        "http://user@gateway.example.test/v1/chat/completions",
        "HTTP://gateway.example.test/v1/chat/completions",
        "ftp://gateway.example.test/v1/chat/completions",
        "ws://gateway.example.test/v1/chat/completions",
    ] {
        assert!(transport::gateway_endpoint(bad).is_err(), "{bad}");
    }
    // How `Gateway::metered` pairs the scheme with trust anchors is tested with the inference
    // codec, in `provider_inference`'s authentication tests.
}

#[test]
fn trust_bundles_replace_roots_and_fail_closed() {
    let ca = Ca::new();
    let url = fixture::url(8443);
    assert!(ProviderTransport::new(&url, Trust::Bundle(&ca.pem()), &[]).is_ok());
    let mut with_other = ca.pem();
    with_other.extend_from_slice(b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n");
    let mut two = ca.pem();
    two.extend_from_slice(&Ca::new().pem());
    assert!(ProviderTransport::new(&url, Trust::Bundle(&two), &[]).is_ok());
    for bad in [
        Vec::new(),
        b"not pem".to_vec(),
        with_other,
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_vec(),
        vec![b'A'; MAX_TRUST_BUNDLE_BYTES + 1],
    ] {
        assert_eq!(
            ProviderTransport::new(&url, Trust::Bundle(&bad), &[]).unwrap_err(),
            Error::Configuration
        );
    }
}

fn answers(list: Vec<SocketAddr>) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> {
    move |_, _| Ok(list.clone())
}
fn at(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip(s), port)
}

#[tokio::test]
async fn valid_exchange_sends_exactly_one_bounded_request() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(br#"{"ok":true}"#))
    })
    .await;
    let t = fixture::transport(server.port, &ca);
    let response = t
        .call(fixture::token_request(&fixture::url(server.port)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), br#"{"ok":true}"#);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    let head = server.heads.lock().unwrap()[0].to_ascii_lowercase();
    assert!(head.starts_with("post /token http/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("\r\nhost: {}:{}\r\n", fixture::HOST, server.port)));
    assert!(head.contains("\r\nconnection: close\r\n"));
    assert!(head.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"));
    for absent in [
        "authorization",
        "cookie",
        "proxy-",
        "accept-encoding",
        "te:",
        "upgrade",
    ] {
        assert!(!head.contains(absent), "{absent}");
    }
}

#[tokio::test]
async fn redirects_are_returned_never_followed() {
    let ca = Ca::new();
    let elsewhere = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    for status in [302, 307] {
        let location = fixture::url(elsewhere.port);
        let server = Server::start(ca.leaf(fixture::HOST, false), move |_| {
            Reply::Bytes(fixture::response(status, &[("location", &location)], b""))
        })
        .await;
        let response = fixture::transport(server.port, &ca)
            .call(fixture::token_request(&fixture::url(server.port)))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }
    assert_eq!(elsewhere.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_destination_method_or_headers_fail_before_dns_or_connect() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let counter = lookups.clone();
    let t = fixture::transport(server.port, &ca).with_lookup(move |h, p| {
        counter.fetch_add(1, Ordering::SeqCst);
        fixture::loopback(h, p)
    });
    let url = fixture::url(server.port);
    let mut cases = Vec::new();
    for other in [
        format!("https://other.example.test:{}/token", server.port),
        format!("https://{}:{}/token", fixture::HOST, server.port + 1),
        format!("https://{}:{}/token2", fixture::HOST, server.port),
        format!("https://{}:{}/token?x=1", fixture::HOST, server.port),
        format!("http://{}:{}/token", fixture::HOST, server.port),
    ] {
        cases.push(fixture::token_request(&other));
    }
    let mut get = fixture::token_request(&url);
    *get.method_mut() = http::Method::GET;
    cases.push(get);
    let mut old = fixture::token_request(&url);
    *old.version_mut() = http::Version::HTTP_10;
    cases.push(old);
    for (name, value) in [
        ("authorization", "Basic c2VjcmV0"),
        ("cookie", "session=secret"),
        ("proxy-authorization", "Basic c2VjcmV0"),
        ("host", "attacker.example.test"),
        ("x-forwarded-for", "127.0.0.1"),
        ("transfer-encoding", "chunked"),
        ("accept", "application/json"),
    ] {
        let mut r = fixture::token_request(&url);
        r.headers_mut().append(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static(value),
        );
        cases.push(r);
    }
    let mut big = fixture::token_request(&url);
    *big.body_mut() = vec![b'a'; MAX_REQUEST_BODY_BYTES + 1];
    cases.push(big);
    for request in cases {
        assert_eq!(t.call(request).await.unwrap_err(), Error::Destination);
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn production_policy_refuses_fixture_and_mixed_answers_before_connect() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let url = fixture::url(server.port);
    let p = server.port;
    // The production constructor alone: loopback is refused even with an allowlist.
    for ranges in [&[][..], &["10.0.0.0/8", "fc00::/7"][..]] {
        let t = ProviderTransport::new(&url, Trust::Bundle(&ca.pem()), ranges)
            .unwrap()
            .with_lookup(fixture::loopback);
        assert_eq!(
            t.call(fixture::token_request(&url)).await.unwrap_err(),
            Error::Address
        );
    }
    // With the fixture seam, every answer must still pass: one bad answer refuses them all.
    for list in [
        vec![at("127.0.0.1", p), at("169.254.169.254", p)],
        vec![at("127.0.0.1", p), at("10.0.0.1", p)],
        vec![at("127.0.0.1", p), at("::ffff:127.0.0.1", p)],
        vec![at("127.0.0.1", p), at("8.8.8.8", p), at("fd00:ec2::254", p)],
        vec![at("127.0.0.1", p + 1)],
    ] {
        let t = fixture::transport(p, &ca).with_lookup(answers(list));
        assert_eq!(
            t.call(fixture::token_request(&url)).await.unwrap_err(),
            Error::Address
        );
    }
    for list in [vec![], vec![at("127.0.0.1", p); MAX_ADDRESSES + 1]] {
        let t = fixture::transport(p, &ca).with_lookup(answers(list));
        assert_eq!(
            t.call(fixture::token_request(&url)).await.unwrap_err(),
            Error::Resolve
        );
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    // The maximum answer count is accepted, and only the validated address is dialled.
    let t =
        fixture::transport(p, &ca).with_lookup(answers(vec![at("127.0.0.1", p); MAX_ADDRESSES]));
    assert!(t.call(fixture::token_request(&url)).await.is_ok());
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn untrusted_wrong_host_or_expired_certificates_send_no_http() {
    let ca = Ca::new();
    for identity in [
        Ca::new().leaf(fixture::HOST, false),
        ca.leaf("other.example.test", false),
        ca.leaf(fixture::HOST, true),
    ] {
        let server = Server::start(identity, |_| Reply::Bytes(fixture::json(b"{}"))).await;
        let err = fixture::transport(server.port, &ca)
            .call(fixture::token_request(&fixture::url(server.port)))
            .await
            .unwrap_err();
        assert_eq!(err, Error::Tls);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_eq!(server.requests.load(Ordering::SeqCst), 0);
    }
}

async fn scripted(
    reply: impl Fn() -> Reply + Send + Sync + 'static,
) -> Result<HttpResponse, Error> {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), move |_| reply()).await;
    let result = fixture::transport(server.port, &ca)
        .with_limits(
            Arc::new(Semaphore::new(1)),
            Duration::from_secs(5),
            Duration::from_millis(500),
        )
        .call(fixture::token_request(&fixture::url(server.port)))
        .await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    result
}
fn raw(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[tokio::test]
async fn response_size_and_header_limits() {
    let exact = vec![b'x'; MAX_RESPONSE_BYTES];
    let ok = scripted(move || Reply::Bytes(fixture::json(&exact)))
        .await
        .unwrap();
    assert_eq!(ok.body().len(), MAX_RESPONSE_BYTES);
    // Declared length over the bound fails before any body byte is read.
    assert_eq!(
        scripted(|| Reply::Stall(raw("HTTP/1.1 200 OK\r\ncontent-length: 65537\r\n\r\n")))
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    let mut chunked = raw("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
    for _ in 0..17 {
        chunked.extend_from_slice(b"1000\r\n");
        chunked.extend_from_slice(&[b'x'; 4096]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(
        scripted(move || Reply::Bytes(chunked.clone()))
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    let headers = |count: usize, size: usize| {
        let mut r = String::from("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n");
        for i in 0..count {
            r.push_str(&format!("x-h{i}: {}\r\n", "v".repeat(size)));
        }
        r.push_str("\r\n{}");
        r.into_bytes()
    };
    let at_limit = headers(MAX_RESPONSE_HEADERS - 1, 1);
    assert!(
        scripted(move || Reply::Bytes(at_limit.clone()))
            .await
            .is_ok()
    );
    let over = headers(MAX_RESPONSE_HEADERS, 1);
    assert_eq!(
        scripted(move || Reply::Bytes(over.clone()))
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    let heavy = headers(10, 1000);
    assert_eq!(
        scripted(move || Reply::Bytes(heavy.clone()))
            .await
            .unwrap_err(),
        Error::TooLarge
    );
}

#[tokio::test]
async fn ambiguous_framing_encoding_and_trailers_are_refused() {
    for bad in [
        "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\ncontent-length: +2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\n\r\n{}",
        "HTTP/1.0 200 OK\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nx-trailer: a\r\n\r\n",
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n",
        "HTTP/2 200\r\ncontent-length: 2\r\n\r\n{}",
        "garbage\r\n\r\n",
    ] {
        let bytes = raw(bad);
        assert_eq!(
            scripted(move || Reply::Bytes(bytes.clone()))
                .await
                .unwrap_err(),
            Error::Protocol,
            "{bad}"
        );
    }
    for good in [
        "HTTP/1.1 200 OK\r\ncontent-encoding: identity\r\ncontent-length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}",
        "HTTP/1.1 204 No Content\r\n\r\n",
    ] {
        let bytes = raw(good);
        assert!(
            scripted(move || Reply::Bytes(bytes.clone())).await.is_ok(),
            "{good}"
        );
    }
}

#[tokio::test]
async fn slow_headers_bodies_and_endless_interim_responses_hit_the_deadline() {
    let replies: [fn() -> Reply; 4] = [
        || Reply::Stall(Vec::new()),
        || Reply::Stall(raw("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{")),
        || {
            Reply::Drip(
                raw("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n"),
                raw("1\r\nx\r\n"),
            )
        },
        || Reply::Drip(Vec::new(), raw("HTTP/1.1 102 Processing\r\n\r\n")),
    ];
    for reply in replies {
        assert_eq!(scripted(reply).await.unwrap_err(), Error::Timeout);
    }
}

#[tokio::test]
async fn ambiguous_post_send_failure_is_not_retried() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Close).await;
    // Two validated answers: the second is never dialled once request bytes were sent.
    let p = server.port;
    let t = fixture::transport(p, &ca)
        .with_lookup(move |_, _| Ok(vec![at("127.0.0.1", p), at("127.0.0.1", p)]));
    assert_eq!(
        t.call(fixture::token_request(&fixture::url(server.port)))
            .await
            .unwrap_err(),
        Error::Protocol
    );
    tokio::task::yield_now().await;
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_alternates_only_before_request_bytes() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    // The fixture listens on IPv4 only, so [::1] refuses TCP and the next answer is tried.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = closed.local_addr().unwrap().port();
    drop(closed);
    let p = server.port;
    let t = fixture::transport(p, &ca)
        .with_lookup(move |_, _| Ok(vec![at("::1", p), at("127.0.0.1", p)]));
    assert!(
        t.call(fixture::token_request(&fixture::url(p)))
            .await
            .is_ok()
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    // Answers must carry the configured port, so a refused port is never an alternate.
    let t = fixture::transport(p, &ca).with_lookup(answers(vec![at("127.0.0.1", dead)]));
    assert_eq!(
        t.call(fixture::token_request(&fixture::url(p)))
            .await
            .unwrap_err(),
        Error::Address
    );
}

#[tokio::test]
async fn cancellation_closes_the_connection() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Stall(Vec::new())).await;
    let t = fixture::transport(server.port, &ca);
    let mut call = Box::pin(t.call(fixture::token_request(&fixture::url(server.port))));
    tokio::select! {
        _ = server.entered.notified() => (),
        _ = &mut call => panic!("stalled provider completed"),
    }
    drop(call);
    tokio::time::timeout(Duration::from_secs(5), server.closed.notified())
        .await
        .expect("dropping the request closes the socket");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

/// Blocks lookups until released; counts entries.
#[derive(Default)]
struct Gate {
    entered: AtomicUsize,
    released: Mutex<usize>,
    wake: Condvar,
    signal: tokio::sync::Notify,
}
impl Gate {
    fn lookup(self: &Arc<Self>) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + use<> {
        let gate = self.clone();
        move |_, _| {
            gate.entered.fetch_add(1, Ordering::SeqCst);
            gate.signal.notify_one();
            let mut released = gate.released.lock().unwrap();
            while *released == 0 {
                released = gate.wake.wait(released).unwrap();
            }
            *released -= 1;
            Err(io::Error::other("synthetic"))
        }
    }
    async fn wait_entered(&self, n: usize) {
        while self.entered.load(Ordering::SeqCst) < n {
            self.signal.notified().await;
        }
    }
    fn release(&self, n: usize) {
        *self.released.lock().unwrap() += n;
        self.wake.notify_all();
    }
}
/// Releases every blocked lookup even when an assertion fails, so runtime shutdown cannot hang.
struct Unblock(Arc<Gate>);
impl Drop for Unblock {
    fn drop(&mut self) {
        self.0.release(1024);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_dns_lookups_keep_their_bounded_slots_until_finished() {
    let ca = Ca::new();
    let gate = Arc::new(Gate::default());
    let _unblock = Unblock(gate.clone());
    let slots = Arc::new(Semaphore::new(DNS_LOOKUP_SLOTS));
    let url = fixture::url(8443);
    let make = || {
        fixture::transport(8443, &ca)
            .with_lookup(gate.lookup())
            .with_limits(
                slots.clone(),
                Duration::from_millis(300),
                Duration::from_secs(1),
            )
    };
    for n in 1..=DNS_LOOKUP_SLOTS {
        let t = make();
        let call = t.call(fixture::token_request(&url));
        tokio::pin!(call);
        tokio::select! {
            _ = gate.wait_entered(n) => (),
            _ = &mut call => panic!("blocked lookup completed"),
        }
    }
    // Every request was dropped, yet every slot is still owned by its unfinished lookup.
    assert_eq!(slots.available_permits(), 0);
    assert_eq!(
        make().call(fixture::token_request(&url)).await.unwrap_err(),
        Error::Timeout
    );
    assert_eq!(gate.entered.load(Ordering::SeqCst), DNS_LOOKUP_SLOTS);
    // Finishing one lookup returns exactly one slot, which a new request can use.
    gate.release(1);
    drop(
        tokio::time::timeout(Duration::from_secs(5), slots.acquire())
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(slots.available_permits(), 1);
    let t = make();
    let call = t.call(fixture::token_request(&url));
    tokio::pin!(call);
    tokio::select! {
        _ = gate.wait_entered(DNS_LOOKUP_SLOTS + 1) => (),
        _ = &mut call => panic!("blocked lookup completed"),
    }
    // Condvar wake order is arbitrary, so release every remaining lookup before awaiting it.
    gate.release(DNS_LOOKUP_SLOTS);
    assert_eq!(call.await.unwrap_err(), Error::Resolve);
    drop(
        tokio::time::timeout(
            Duration::from_secs(5),
            slots.acquire_many(DNS_LOOKUP_SLOTS as u32),
        )
        .await
        .unwrap()
        .unwrap(),
    );
}

#[test]
fn production_dns_pool_is_process_wide_and_fixed() {
    let ca = Ca::new();
    let a = ProviderTransport::new(&fixture::url(8443), Trust::Bundle(&ca.pem()), &[]).unwrap();
    let b = ProviderTransport::new(&fixture::url(8444), Trust::Bundle(&ca.pem()), &[]).unwrap();
    assert!(Arc::ptr_eq(&a.slots, &b.slots));
    assert!(Arc::ptr_eq(&a.slots, &DNS_SLOTS));
    assert!(DNS_SLOTS.available_permits() <= DNS_LOOKUP_SLOTS);
    assert_eq!((a.setup, a.total), (SETUP_DEADLINE, TOTAL_DEADLINE));
    assert!(!a.loopback);
}

#[test]
fn errors_and_debug_are_redacted() {
    let ca = Ca::new();
    let t = ProviderTransport::new(
        "https://secret-host.example.test/secret-path",
        Trust::Bundle(&ca.pem()),
        &["10.20.0.0/24"],
    )
    .unwrap();
    let text = format!("{t:?}");
    assert!(!text.contains("secret") && !text.contains("10.20"));
    for e in [
        Error::Configuration,
        Error::Destination,
        Error::Resolve,
        Error::Address,
        Error::Connect,
        Error::Tls,
        Error::Protocol,
        Error::TooLarge,
        Error::Timeout,
    ] {
        let text = format!("{e} {e:?}");
        assert!(!text.contains("secret") && !text.contains("example") && !text.contains('/'));
    }
}

const PROXY_CHILD: &str = "OPENMETTLE_PROVIDER_HTTP_PROXY_CHILD";

/// Runs in a child process with proxy variables set by the parent; skipped otherwise.
#[tokio::test]
#[ignore = "child process of environment_proxies_are_ignored"]
async fn environment_proxy_child() {
    if std::env::var(PROXY_CHILD).as_deref() != Ok("1") {
        return;
    }
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    fixture::transport(server.port, &ca)
        .call(fixture::token_request(&fixture::url(server.port)))
        .await
        .unwrap();
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

#[test]
fn environment_proxies_are_ignored() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", proxy.local_addr().unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "provider_http::tests::environment_proxy_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env(PROXY_CHILD, "1");
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        child.env(name, &address);
    }
    child.env_remove("NO_PROXY").env_remove("no_proxy");
    let output = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    proxy.set_nonblocking(true).unwrap();
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "a proxy connection was made"
    );
}

#[tokio::test]
async fn document_get_capabilities_keep_destination_method_and_stream_bounds() {
    let ca = fixture::Ca::new();
    let server = fixture::Server::start(ca.leaf(fixture::HOST, false), |received| {
        assert!(
            received.head.starts_with("GET /discovery ") || received.head.starts_with("GET /jwks ")
        );
        assert!(received.body.is_empty());
        fixture::Reply::Bytes(fixture::response(
            200,
            &[("content-type", "application/json")],
            b"{}",
        ))
    })
    .await;
    let token = fixture::transport(server.port, &ca);
    let base = format!("https://{}:{}", fixture::HOST, server.port);
    let documents = ProviderDocuments::configured(
        &token,
        &format!("{base}/discovery"),
        &format!("{base}/jwks"),
    )
    .unwrap();
    documents.fetch_discovery().await.unwrap();
    documents.fetch_jwks().await.unwrap();
    for path in ["/token", "/other", "/discovery?query=yes"] {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("{base}{path}"))
            .body(vec![])
            .unwrap();
        assert_eq!(
            documents.discovery.send(request).await.unwrap_err(),
            Error::Destination
        );
    }
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("{base}/discovery"))
        .body(vec![])
        .unwrap();
    assert_eq!(
        documents.discovery.send(request).await.unwrap_err(),
        Error::Destination
    );
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("{base}/discovery"))
        .header("authorization", "synthetic-marker")
        .body(vec![])
        .unwrap();
    assert_eq!(
        documents.discovery.send(request).await.unwrap_err(),
        Error::Destination
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    let oversized = fixture::Server::start(ca.leaf(fixture::HOST, false), |_| {
        fixture::Reply::Stall(b"HTTP/1.1 200 OK\r\ncontent-length: 65537\r\n\r\n".to_vec())
    })
    .await;
    let token = fixture::transport(oversized.port, &ca);
    let url = fixture::url(oversized.port);
    let documents = ProviderDocuments::configured(&token, &url, &url).unwrap();
    assert_eq!(documents.fetch_jwks().await.unwrap_err(), Error::TooLarge);
}

#[tokio::test]
async fn turn_dispatch_sends_to_originating_gateway_with_bound_request_id() {
    use crate::model_config::{Catalog, Selection};
    use crate::provider_http::inference::{
        Gateway, History, Protocol, Qualification, Request, RunStop, Timeouts,
    };
    use crate::worker::ActiveRun;
    use tokio::sync::watch;

    let ca = fixture::Ca::new();
    let expected_id = "00000000-0000-4000-8000-000000001919";
    let expected_bearer = "turn-dispatch-wire-bearer";
    let server = fixture::Server::start(ca.leaf(fixture::HOST, false), move |received| {
        assert!(
            received
                .head
                .starts_with("POST /v1/chat/completions HTTP/1.1\r\n")
        );
        let header_val = |name: &str| {
            received
                .head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_owned())
        };
        assert_eq!(
            header_val("authorization").as_deref(),
            Some(format!("Bearer {expected_bearer}").as_str())
        );
        assert_eq!(header_val("x-request-id").as_deref(), Some(expected_id));
        let body = serde_json::json!({
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "bound ok"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2}
        });
        fixture::Reply::Bytes(fixture::response(
            200,
            &[("content-type", "application/json")],
            body.to_string().as_bytes(),
        ))
    })
    .await;

    let catalog =
        Catalog::load(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let effective = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(serde_json::json!({"preset": "study"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let mut gateway = Gateway::new(
        &format!(
            "https://{}:{}/v1/chat/completions",
            fixture::HOST,
            server.port
        ),
        Trust::Bundle(&ca.pem()),
        &[],
        Qualification {
            model: effective.model.clone(),
            pin: effective.profile.clone(),
            protocol: Protocol::Chat,
            json: true,
            sse: false,
            functions: None,
            images: false,
            parallel: false,
            usage: true,
            tool_separator_whitespace: false,
        },
        Timeouts {
            setup: Duration::from_secs(5),
            idle: Duration::from_secs(5),
            overall: Duration::from_secs(10),
        },
    )
    .unwrap();
    let port = server.port;
    gateway.fixture_lookup(Arc::new(move |_, _| {
        Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
    }));

    let req = Request {
        history: vec![History::User("hello turn dispatch".into())],
        tools: None,
        parallel: None,
        stream: false,
    };
    let prepared = gateway.prepare(&catalog, &effective, &req, true).unwrap();
    let dispatch = Dispatch {
        id: expected_id.to_owned(),
        installation: "00000000-0000-4000-8000-000000001918".to_owned(),
        model: effective.model.clone(),
        server: true,
        authorization: HeaderValue::from_str(&format!("Bearer {expected_bearer}")).unwrap(),
    };
    let turn_dispatch = TurnDispatch::new(dispatch, prepared);
    let (_tx, stop_rx) = watch::channel(None);
    let run = ActiveRun {
        claim: crate::authz::runs::ClaimedRun {
            scope_id: "s".into(),
            run_id: "r".into(),
            claim_token: "t".into(),
            actor_approval_id: "a".into(),
            round_limit: 1,
            lease_remaining: Duration::from_secs(10),
            execution_remaining: Duration::from_secs(10),
        },
        state: crate::authz::leases::ExecState::Running,
        execution_deadline: tokio::time::Instant::now() + Duration::from_secs(10),
    };
    let turn = turn_dispatch
        .send(RunStop::from_worker(&run, stop_rx), |_| async {})
        .await
        .unwrap();
    assert_eq!(turn.answers[0].parts, ["bound ok"]);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

/// The metered gateway route over plain HTTP (ADR 0044): the committed dispatch's bearer and
/// `x-request-id` reach the server on a TCP connection that carries no TLS handshake.
#[tokio::test]
async fn plain_http_turn_dispatch_sends_its_bearer_and_request_id_without_tls() {
    use crate::model_config::{Catalog, Selection};
    use crate::provider_http::inference::{
        Gateway, History, Protocol, Qualification, Request, RunStop, Timeouts,
    };
    use crate::worker::ActiveRun;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::watch,
    };

    let id = "00000000-0000-4000-8000-000000001920";
    let bearer = "plain-turn-dispatch-wire-bearer";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        let head = loop {
            let n = socket.read(&mut buffer).await.unwrap();
            assert!(n > 0, "the request head ended early");
            received.extend_from_slice(&buffer[..n]);
            if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break String::from_utf8(received[..end + 4].to_vec()).unwrap();
            }
        };
        let body = br#"{"choices":[{"index":0,"message":{"role":"assistant","content":"plain ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        // A TLS client would have opened with a handshake record (0x16), not a request line.
        (received[0], head)
    });

    let catalog =
        Catalog::load(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let effective = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(serde_json::json!({"preset": "study"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let mut gateway = Gateway::metered(
        &format!("http://{}:{port}/v1/chat/completions", fixture::HOST),
        None,
        &[],
        Qualification {
            model: effective.model.clone(),
            pin: effective.profile.clone(),
            protocol: Protocol::Chat,
            json: true,
            sse: false,
            functions: None,
            images: false,
            parallel: false,
            usage: true,
            tool_separator_whitespace: false,
        },
        Timeouts {
            setup: Duration::from_secs(5),
            idle: Duration::from_secs(5),
            overall: Duration::from_secs(10),
        },
    )
    .unwrap();
    gateway.fixture_lookup(Arc::new(move |_, _| {
        Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
    }));
    let request = Request {
        history: vec![History::User("hello plain dispatch".into())],
        tools: None,
        parallel: None,
        stream: false,
    };
    let prepared = gateway
        .prepare(&catalog, &effective, &request, true)
        .unwrap();
    let dispatch = Dispatch {
        id: id.to_owned(),
        installation: "00000000-0000-4000-8000-000000001918".to_owned(),
        model: effective.model.clone(),
        server: true,
        authorization: HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
    };
    let (_stop, stop) = watch::channel(None);
    let run = ActiveRun {
        claim: crate::authz::runs::ClaimedRun {
            scope_id: "s".into(),
            run_id: "r".into(),
            claim_token: "t".into(),
            actor_approval_id: "a".into(),
            round_limit: 1,
            lease_remaining: Duration::from_secs(10),
            execution_remaining: Duration::from_secs(10),
        },
        state: crate::authz::leases::ExecState::Running,
        execution_deadline: tokio::time::Instant::now() + Duration::from_secs(10),
    };
    let turn = TurnDispatch::new(dispatch, prepared)
        .send(RunStop::from_worker(&run, stop), |_| async {})
        .await
        .unwrap();
    assert_eq!(turn.answers[0].parts, ["plain ok"]);
    let (first, head) = server.await.unwrap();
    assert_eq!(first, b'P');
    let head = head.to_ascii_lowercase();
    assert!(
        head.starts_with("post /v1/chat/completions http/1.1\r\n"),
        "{head}"
    );
    for line in [
        format!("host: {}:{port}", fixture::HOST),
        format!("authorization: bearer {bearer}"),
        format!("x-request-id: {id}"),
        "connection: close".to_owned(),
    ] {
        assert!(head.contains(&format!("\r\n{line}\r\n")), "{line}: {head}");
    }
}

#[tokio::test]
async fn billable_dispatch_follows_mode_and_requires_output_cap() {
    use crate::{
        model_config::{Catalog, Selection},
        provider_http::{
            BillableDispatch, BillableInferenceRef,
            inference::{Gateway, History, Protocol, Qualification, Request, RunStop, Timeouts},
        },
        worker::ActiveRun,
    };
    use std::sync::atomic::Ordering;
    use tokio::sync::watch;

    let ca = fixture::Ca::new();
    let expected_id = "00000000-0000-4000-8000-000000002101";
    let expected_bearer = "synthetic-billable-dispatch-token";
    let server = fixture::Server::start(ca.leaf(fixture::HOST, false), move |req| {
        assert!(
            req.head
                .contains(&format!("x-request-id: {expected_id}\r\n")),
            "missing x-request-id: {}",
            req.head
        );
        assert!(
            req.head
                .contains(&format!("authorization: Bearer {expected_bearer}\r\n")),
            "missing bearer header: {}",
            req.head
        );
        fixture::Reply::Bytes(fixture::json(
            br#"{"choices":[{"index":0,"message":{"role":"assistant","content":"billable ok"},"finish_reason":"stop"}]}"#,
        ))
    })
    .await;

    let catalog =
        Catalog::load(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let missing_cap = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(serde_json::json!({
                "model": "a",
                "layer": {"controls": {"context_window": 100}}
            }))
            .unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let valid_eff = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(serde_json::json!({
                "model": "a",
                "layer": {"controls": {"context_window": 100, "output_reserve": 40}}
            }))
            .unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let mut gateway = Gateway::new(
        &format!(
            "https://{}:{}/v1/chat/completions",
            fixture::HOST,
            server.port
        ),
        Trust::Bundle(&ca.pem()),
        &[],
        Qualification {
            model: valid_eff.model.clone(),
            pin: valid_eff.profile.clone(),
            protocol: Protocol::Chat,
            json: true,
            sse: false,
            functions: None,
            images: false,
            parallel: false,
            usage: true,
            tool_separator_whitespace: false,
        },
        Timeouts {
            setup: Duration::from_secs(5),
            idle: Duration::from_secs(5),
            overall: Duration::from_secs(10),
        },
    )
    .unwrap();
    let port = server.port;
    gateway.fixture_lookup(Arc::new(move |_, _| {
        Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
    }));
    let billable = BillableInferenceRef {
        installation: "00000000-0000-4000-8000-000000002102",
        route: &gateway,
    };
    let req = Request {
        history: vec![History::User("hello billable dispatch".into())],
        tools: None,
        parallel: None,
        stream: false,
    };

    // Missing output_reserve fails BillableInferenceRef::prepare for BOTH caller and server modes.
    assert_eq!(
        billable.prepare(&catalog, &missing_cap, &req, false).err(),
        Some(crate::provider_http::inference::Error::Validation)
    );
    assert_eq!(
        billable.prepare(&catalog, &missing_cap, &req, true).err(),
        Some(crate::provider_http::inference::Error::Validation)
    );

    let mk_dispatch = |server_flag: bool| Dispatch {
        id: expected_id.to_owned(),
        installation: "00000000-0000-4000-8000-000000002102".to_owned(),
        model: valid_eff.model.clone(),
        server: server_flag,
        authorization: HeaderValue::from_str(&format!("Bearer {expected_bearer}")).unwrap(),
    };
    let (_tx, stop_rx) = watch::channel(None);
    let run = ActiveRun {
        claim: crate::authz::runs::ClaimedRun {
            scope_id: "s".into(),
            run_id: "r".into(),
            claim_token: "t".into(),
            actor_approval_id: "a".into(),
            round_limit: 1,
            lease_remaining: Duration::from_secs(10),
            execution_remaining: Duration::from_secs(10),
        },
        state: crate::authz::leases::ExecState::Running,
        execution_deadline: tokio::time::Instant::now() + Duration::from_secs(10),
    };

    // The validated request mode selects the variant, so each committed dispatch exposes only
    // its matching send and each transmits once with x-request-id.
    let BillableDispatch::Caller(caller) = BillableDispatch::new(
        mk_dispatch(false),
        billable.prepare(&catalog, &valid_eff, &req, false).unwrap(),
    ) else {
        panic!("a caller-mode request must yield BillableDispatch::Caller");
    };
    let caller_turn = caller.send(|_| async {}).await.unwrap();
    assert_eq!(caller_turn.answers[0].parts, ["billable ok"]);
    let BillableDispatch::Server(leased) = BillableDispatch::new(
        mk_dispatch(true),
        billable.prepare(&catalog, &valid_eff, &req, true).unwrap(),
    ) else {
        panic!("a server-mode request must yield BillableDispatch::Server");
    };
    let server_turn = leased
        .send(RunStop::from_worker(&run, stop_rx), |_| async {})
        .await
        .unwrap();
    assert_eq!(server_turn.answers[0].parts, ["billable ok"]);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
}
