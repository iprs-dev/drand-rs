use super::*;

#[test]
fn test_client_empty_endpoint() {
    let config = Config::default();
    let mut client = Client::from_config("test", config);

    assert!(client.to_info().is_ok());
    assert!(client.boot(None).is_err());
    assert!(client.get(None).is_err());
}

#[test]
fn test_client_1_no_determinism() {
    // with rot
    // without rot
    // invalid rot
    todo!()
}

#[test]
fn test_client_1_assumed_determinism() {
    todo!()
}

#[test]
fn test_client_1_reestablish_determinism() {
    todo!()
}

#[test]
fn test_client_1_continued_determinism() {
    todo!()
}
