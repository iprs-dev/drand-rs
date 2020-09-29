use crate::{Error, Random, Result};

pub(crate) fn verify_chain(pk: &[u8], previous_signature: &[u8], curr: &Random) -> Result<bool> {
    if previous_signature != curr.previous_signature.as_slice() {
        let s = hex::encode(previous_signature);
        let p = hex::encode(&curr.previous_signature);
        err_at!(NotSecure, msg: format!("mismatch chain {:?} != {:?}", s, p))?
    }

    let pk = {
        let mut bytes: [u8; 48] = [0_u8; 48];
        bytes[..].clone_from_slice(&pk);
        err_at!(NotSecure, drand_verify::g1_from_fixed(bytes))?
    };

    Ok(err_at!(
        NotSecure,
        drand_verify::verify(
            &pk,
            curr.round as u64,
            &curr.previous_signature,
            &curr.signature
        )
    )?)
}

#[cfg(test)]
#[path = "verify_test.rs"]
mod verify_test;
