// TODO: Is it okay to use http calls to the league network in
// unit-test case ? Or should we use a mock server ?

use super::*;

#[test]
fn test_verify() {
    use crate::http::Http;
    use hex_literal::hex;

    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let mut endp = Http::new_drand_api();
    let client = reqwest::Client::new();

    let (info, _) = rt.block_on(endp.boot_phase1(None, None)).unwrap();
    let r1 = rt.block_on(endp.do_get(&client, Some(1))).unwrap();
    let r2 = rt.block_on(endp.do_get(&client, Some(2))).unwrap();

    assert!(verify_chain(&info.public_key, &info.group_hash, &r1).unwrap());
    assert!(verify_chain(&info.public_key, &r1.signature, &r2).unwrap());
}
