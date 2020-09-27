// TODO: Is it okay to use http calls to the league network in
// unit-test case ? Or should we use a mock server ?

use super::*;

#[test]
fn test_base_url() {
    assert_eq!(Http::new_drand_api().to_base_url(), "https://api.drand.sh");
}

#[test]
fn test_elapsed() {
    let mut endp = Http::new_drand_api();

    for _ in 0..MAX_ELAPSED_WINDOW {
        endp.add_elapsed(time::Duration::from_secs(10))
    }
    assert_eq!(endp.to_elapsed(), time::Duration::from_secs(10));

    for i in 0..(MAX_ELAPSED_WINDOW - 1) {
        endp.add_elapsed(MAX_ELAPSED);
        assert_ne!(endp.to_elapsed(), MAX_ELAPSED, "for {}th", i)
    }
    endp.add_elapsed(MAX_ELAPSED);
    assert_eq!(endp.to_elapsed(), MAX_ELAPSED);
}

#[test]
fn test_get_info() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let endp = Http::new_drand_api();
    let client = reqwest::Client::new();

    let info: Info = rt
        .block_on(async {
            let url = make_url!("info", endp.to_base_url());
            let resp = client.get(url.as_str()).send().await.unwrap();
            let info: InfoJson = err_at!(JsonParse, resp.json().await)?;
            Ok::<Info, Error>(info.try_into()?)
        })
        .unwrap();

    assert_eq!(
        hex::encode(info.public_key),
        "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"
    );
    assert_eq!(
        info.genesis_time - time::Duration::from_secs(1595431050),
        time::UNIX_EPOCH
    );
    assert_eq!(
        hex::encode(info.hash),
        "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
    );
    assert_eq!(
        hex::encode(info.group_hash),
        "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
    );
}

#[test]
fn test_do_get() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let mut endp = Http::new_drand_api();
    let client = reqwest::Client::new();

    let r = rt.block_on(endp.do_get(&client, Some(1))).unwrap();

    assert_eq!(r.round, 1);
    assert_eq!(
        hex::encode(r.randomness),
        "101297f1ca7dc44ef6088d94ad5fb7ba03455dc33d53ddb412bbc4564ed986ec"
    );
    assert_eq!(
        hex::encode(r.signature),
        "8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655",
    );
    assert_eq!(
        hex::encode(r.previous_signature),
        "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
    );
}

#[test]
fn test_boot_phase1() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let mut endp = Http::new_drand_api();

    let (info, _) = rt.block_on(endp.boot_phase1(None, None)).unwrap();
    assert_eq!(
        hex::encode(info.hash),
        "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
    );
    assert_eq!(
        hex::encode(info.group_hash),
        "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
    );

    // root-of-trust
    let rot =
        hex::decode("8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce").unwrap();
    let (info, _) = rt.block_on(endp.boot_phase1(Some(&rot), None)).unwrap();
    assert_eq!(
        hex::encode(info.hash.clone()),
        "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
    );
    assert_eq!(
        hex::encode(info.group_hash),
        "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
    );

    // invlaid root-of-trust
    let rot = &info.hash[1..];
    assert!(rt.block_on(endp.boot_phase1(Some(rot), None)).is_err());
}
