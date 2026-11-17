use openmettle_core::login::KeyRing;
#[test]
fn keyring_is_bounded_and_rejects_aliases() {
    assert!(KeyRing::new(vec![]).is_err());
    assert!(KeyRing::new(vec![("a".into(), [1; 32]), ("a".into(), [2; 32])]).is_err());
    assert!(KeyRing::new(vec![("a".into(), [1; 32]), ("b".into(), [1; 32])]).is_err());
    assert!(KeyRing::new(vec![("bad id".into(), [1; 32])]).is_err());
    assert!(KeyRing::new((1..=5).map(|i| (i.to_string(), [i; 32])).collect()).is_err());
    let keys = KeyRing::new(vec![("active".into(), [1; 32])]).unwrap();
    assert_eq!(format!("{keys:?}"), "KeyRing(..)");
}
