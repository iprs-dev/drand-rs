use super::*;

#[test]
fn test_client_empty_endpoint() {
    let config = Config {
        check_point: None,
        determinism: false,
        secure: false,
    };

    let mut client = Client::from_config(config);

    assert!(client.to_info().is_ok());
    assert!(client.boot(None).is_err());
    assert!(client.get(None).is_err());
}
