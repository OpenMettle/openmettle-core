use crate::{
    provider_http::{
        Trust,
        fixture::{self, Reply},
        inference::*,
        transport,
    },
    support::*,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// The metered gateway route chooses TLS by its scheme (ADR 0044): `http://` takes no trust
/// anchors but at least one range, and `https://` needs trust anchors. The general constructor
/// keeps `https://` only.
#[test]
fn only_the_metered_gateway_route_may_be_plain_http() {
    let c = catalog(Protocol::Chat, true);
    let e = effective(&c, false);
    let ca = fixture::Ca::new();
    let pem = ca.pem();
    let qualification = || Qualification {
        model: e.model.clone(),
        pin: e.profile.clone(),
        protocol: Protocol::Chat,
        json: true,
        sse: false,
        functions: None,
        images: false,
        parallel: false,
        usage: true,
        tool_separator_whitespace: false,
    };
    let plain = format!("http://{}:8082{}", fixture::HOST, path(Protocol::Chat));
    let secure = format!("https://{}{}", fixture::HOST, path(Protocol::Chat));
    let metered = |url: &str, trust, ranges: &[&str]| {
        Gateway::metered(url, trust, ranges, qualification(), NORMAL)
    };
    let range = ["10.20.0.0/16"];
    assert!(metered(&plain, None, &range).is_ok());
    // A plain route reaches only its configured ranges, so it needs one.
    assert!(metered(&plain, None, &[]).is_err());
    assert!(metered(&plain, Some(Trust::Bundle(&pem)), &range).is_err());
    assert!(metered(&secure, None, &range).is_err());
    assert!(metered(&secure, Some(Trust::Bundle(&pem)), &[]).is_ok());
    assert!(Gateway::new(&plain, Trust::Bundle(&pem), &[], qualification(), NORMAL).is_err());
}

/// Exercise the same inferred operation without the internal credential. This raw client exists
/// only in the test; the adapter cannot send an unauthenticated request.
async fn denial(mock: &Mock, body: &[u8], auth: &str) -> u16 {
    let url = format!(
        "https://{}:{}{}",
        fixture::HOST,
        mock.server.port,
        path(mock.protocol)
    );
    assert_eq!(transport::endpoint(&url).unwrap().url, url);
    let roots = transport::roots(Trust::Bundle(&mock.ca.pem())).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", mock.server.port))
        .await
        .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(transport::client_config(roots).unwrap())
        .connect(fixture::HOST.try_into().unwrap(), tcp)
        .await
        .unwrap();
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\n\r\n",
        path(mock.protocol),
        fixture::HOST,
        mock.server.port,
        body.len()
    );
    tls.write_all(head.as_bytes()).await.unwrap();
    tls.write_all(body).await.unwrap();
    let mut reply = Vec::new();
    tls.read_to_end(&mut reply).await.unwrap();
    std::str::from_utf8(&reply[9..12]).unwrap().parse().unwrap()
}
async fn qualifies(mock: &Mock, stream: bool) -> bool {
    let c = catalog(mock.protocol, true);
    let e = effective(&c, false);
    let g = mock.gateway(&e, NORMAL);
    let success = g
        .caller(
            &c,
            &e,
            &request(stream),
            Credential::Bearer(TOKEN),
            |_| async {},
        )
        .await;
    let positive=success.is_ok_and(|turn|{
        let answer=&turn.answers[0];
        answer.parts==[ANSWER] && answer.reasoning.as_ref().is_some_and(|r|r.blocks[0].to_string().contains(THINK)) && matches!(&answer.calls,CallGroup::Valid(calls) if calls.len()==1 && calls[0].arguments["v"]==ARG)
    });
    let body = mock.captured.lock().unwrap().first().unwrap().to_string();
    let missing = denial(mock, body.as_bytes(), "").await;
    let wrong = denial(
        mock,
        body.as_bytes(),
        "Authorization: Bearer incorrect-fixture\r\n",
    )
    .await;
    positive && missing == 403 && wrong == 403
}
#[tokio::test]
async fn each_route_requires_positive_inference_and_both_negative_probes() {
    for (p, stream) in MODES {
        let bytes = canary_turn(p, stream);
        let allow = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
        assert!(qualifies(&allow, stream).await);
        let deny = Mock::new(p, |_| {
            Reply::Bytes(fixture::response(403, &[], ECHO.as_bytes()))
        })
        .await;
        assert!(!qualifies(&deny, stream).await);
    }
}
