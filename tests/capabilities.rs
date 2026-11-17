use openmettle_core::capabilities::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[tokio::test]
async fn independent_dimensions_and_lazy_observation() {
    for installed in [false, true] {
        for enabled in [false, true] {
            for caller in [
                Caller::Hidden,
                Caller::Visible(Authorization::Allowed),
                Caller::Visible(Authorization::Denied),
                Caller::Visible(Authorization::Unknown),
            ] {
                for status in [
                    Status::Ready,
                    Status::Degraded,
                    Status::Unavailable,
                    Status::Unknown,
                ] {
                    let mut calls = 0;
                    let result = evaluate(
                        Input {
                            installed,
                            enabled,
                            caller,
                        },
                        Duration::from_millis(50),
                        || {
                            calls += 1;
                            async { Observation::Status(status) }
                        },
                    )
                    .await;
                    let queried =
                        installed && enabled && caller == Caller::Visible(Authorization::Allowed);
                    assert_eq!(calls, usize::from(queried));
                    let Caller::Visible(authorization) = caller else {
                        assert!(result.is_none());
                        continue;
                    };
                    let result = result.unwrap();
                    assert_eq!(result.installed, installed);
                    assert_eq!(result.authorization, authorization);
                    assert_eq!(result.readiness.is_some(), installed);
                    if let Some(r) = result.readiness {
                        assert_eq!(r.status, if queried { status } else { Status::Unknown });
                        assert_eq!(
                            r.observed_at.is_some(),
                            queried && status != Status::Unknown
                        );
                        assert_eq!(
                            r.reason,
                            if enabled {
                                None
                            } else {
                                Some(Reason::Disabled)
                            }
                        );
                    }
                    assert_eq!(
                        result.offered(),
                        queried && matches!(status, Status::Ready | Status::Degraded)
                    );
                }
            }
        }
    }
}

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn failure_timeout_and_cancellation_are_bounded() {
    let input = Input {
        installed: true,
        enabled: true,
        caller: Caller::Visible(Authorization::Allowed),
    };
    let failed = evaluate(input, Duration::from_millis(10), || async {
        Observation::ProviderFailure
    })
    .await
    .unwrap();
    let r = failed.readiness.unwrap();
    assert_eq!(r.status, Status::Unavailable);
    assert_eq!(r.reason, Some(Reason::ProviderFailure));
    assert!(r.observed_at.is_some());
    assert!(!failed.offered());
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let timed = tokio::time::timeout(
        Duration::from_secs(1),
        evaluate(input, Duration::ZERO, || async {
            let _guard = guard;
            std::future::pending().await
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        timed.readiness.unwrap(),
        Readiness {
            status: Status::Unknown,
            observed_at: None,
            reason: Some(Reason::Timeout)
        }
    );
    assert!(!timed.offered());

    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let evaluation = evaluate(input, Duration::from_secs(5), || async {
        let _guard = guard;
        std::future::pending().await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(10), evaluation)
            .await
            .is_err()
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn unknown_vocabulary_is_not_success() {
    for code in [
        "unknown",
        "future_ready",
        "READY",
        "",
        "https://synthetic.invalid/private",
    ] {
        let result = evaluate(
            Input {
                installed: true,
                enabled: true,
                caller: Caller::Visible(Authorization::Allowed),
            },
            Duration::from_millis(10),
            || async { Observation::Status(Status::from_code(code)) },
        )
        .await
        .unwrap();
        assert_eq!(result.readiness.unwrap().status, Status::Unknown);
        assert_eq!(result.readiness.unwrap().observed_at, None);
        assert!(!result.offered());
        assert!(!format!("{result:?}").contains(code) || code.is_empty());
    }
}
