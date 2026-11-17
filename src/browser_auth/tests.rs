use super::*;

#[test]
fn only_acknowledged_outcomes_permit_reuse() {
    use login::Error as L;
    use sessions::Error as S;
    assert!(login_settled(&Ok::<_, L>(())));
    assert!(session_settled(&Ok::<_, S>(())));
    for safe in [
        L::Configuration,
        L::Random,
        L::Rejected,
        L::Protection,
        L::Capacity,
        L::Unconfigured,
    ] {
        assert!(login_settled::<()>(&Err(safe)), "{safe:?}");
    }
    for uncertain in [L::Database, L::Exchange, L::Verification] {
        assert!(!login_settled::<()>(&Err(uncertain)), "{uncertain:?}");
    }
    for safe in [S::Configuration, S::Rejected, S::Capacity, S::Random] {
        assert!(session_settled::<()>(&Err(safe)), "{safe:?}");
    }
    for uncertain in [S::Database, S::Timeout] {
        assert!(!session_settled::<()>(&Err(uncertain)), "{uncertain:?}");
    }
}

#[test]
fn errors_keep_the_fixed_domain_text() {
    for (error, text) in [
        (
            Error::from(login::Error::Rejected),
            login::Error::Rejected.to_string(),
        ),
        (
            Error::from(sessions::Error::Timeout),
            sessions::Error::Timeout.to_string(),
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    assert_eq!(
        format!("{:?}", Error::Login(login::Error::Database)),
        "Login(Database)"
    );
}
