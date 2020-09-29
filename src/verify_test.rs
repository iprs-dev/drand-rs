// TODO: Is it okay to use http calls to the league network in
// unit-test case ? Or should we use a mock server ?

use super::*;

#[test]
fn test_verify() {
    use crate::http::Http;

    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let mut endp = Http::new_drand_api();
    let client = reqwest::Client::new();

    let (info, _) = rt.block_on(endp.boot_phase1(None, None)).unwrap();
    let r1 = rt.block_on(endp.do_get(&client, Some(1))).unwrap();
    let r2 = rt.block_on(endp.do_get(&client, Some(2))).unwrap();

    assert!(verify_chain(&info.public_key, &info.group_hash, &r1).unwrap());
    assert!(verify_chain(&info.public_key, &r1.signature, &r2).unwrap());
}

#[test]
fn test_randomness() {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::default();

    let signature = hex::decode("8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655").unwrap();
    hasher.update(&signature);

    assert_eq!(
        "101297f1ca7dc44ef6088d94ad5fb7ba03455dc33d53ddb412bbc4564ed986ec",
        hex::encode(hasher.finalize().to_vec())
    );
}
