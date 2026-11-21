use crate::{
    provider_http::{
        DNS_LOOKUP_SLOTS,
        fixture::{self, Reply},
        inference::*,
    },
    support::*,
};
use serde_json::json;
use std::{
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

#[test]
fn abandoned_gateway_lookups_keep_their_slots() {
    // Saturation belongs in a separate process so parallel matrix cases keep their normal pool.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "dns::gateway_slots_child"])
        .env("OPENMETTLE_GATEWAY_SLOTS_TEST", "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
}
#[tokio::test]
#[ignore = "process-isolated DNS saturation fixture"]
async fn gateway_slots_child() {
    if std::env::var("OPENMETTLE_GATEWAY_SLOTS_TEST").as_deref() != Ok("1") {
        return;
    }
    let p = Protocol::Chat;
    let c = Arc::new(catalog(p, true));
    let e = Arc::new(effective(&c, false));
    let response = wire(
        p,
        false,
        json!({"role":"assistant","content":"resumed"}),
        "stop".into(),
        vec![],
    );
    let mock = Mock::new(p, move |_| Reply::Bytes(response.clone())).await;
    let (entered, mut seen) = mpsc::unbounded_channel();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let held = gate.clone();
    let mut client = mock.gateway(&e, NORMAL);
    client.fixture_lookup(Arc::new(move |h, port| {
        let _ = entered.send(());
        // Safety net for test assertion failures while Tokio waits for the blocking pool.
        let _guard = held
            .1
            .wait_timeout_while(held.0.lock().unwrap(), Duration::from_secs(6), |done| {
                !*done
            })
            .unwrap();
        fixture::loopback(h, port)
    }));
    let g = Arc::new(client);
    let mut work = tokio::task::JoinSet::new();
    for _ in 0..DNS_LOOKUP_SLOTS {
        let (c, e, g) = (c.clone(), e.clone(), g.clone());
        work.spawn(async move {
            g.caller(
                &c,
                &e,
                &request(false),
                Credential::Bearer(TOKEN),
                |_| async {},
            )
            .await
        });
    }
    for _ in 0..DNS_LOOKUP_SLOTS {
        timeout(Duration::from_secs(2), seen.recv())
            .await
            .unwrap()
            .unwrap();
    }
    work.shutdown().await;
    let mut short = NORMAL;
    short.setup = Duration::from_millis(100);
    let fresh = mock.gateway(&e, short);
    assert_eq!(
        fresh
            .caller(
                &c,
                &e,
                &request(false),
                Credential::Bearer(TOKEN),
                |_| async {}
            )
            .await
            .err(),
        Some(Error::Timeout)
    );
    mock.assert_inference_only(0);
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let resumed = mock
        .gateway(&e, NORMAL)
        .caller(
            &c,
            &e,
            &request(false),
            Credential::Bearer(TOKEN),
            |_| async {},
        )
        .await
        .unwrap();
    assert_eq!(resumed.answers[0].parts, ["resumed"]);
    mock.assert_inference_only(1);
}
