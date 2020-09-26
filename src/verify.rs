use crate::{Error, Random, Result};

pub(crate) fn verify_chain(pk: &[u8], prev: &Random, curr: &Random) -> Result<bool> {
    use std::str::from_utf8;

    let psign = &curr.previous_signature;

    if &prev.signature != psign {
        let (s, p) = (&prev.signature, psign);
        // TODO: display as hex.
        err_at!(Fatal, msg: format!("mismatch chain {:?} != {:?}", s, p))?
    }

    let pk = {
        let mut bytes: [u8; 48] = [0_u8; 48];
        let s = err_at!(Parse, from_utf8(&pk))?;
        bytes[..].clone_from_slice(&err_at!(Parse, hex::decode(&s))?);
        err_at!(Parse, drand_verify::g1_from_fixed(bytes))?
    };

    let psign = err_at!(Parse, hex::decode(psign))?;
    let sign = err_at!(Parse, hex::decode(&curr.signature))?;
    Ok(err_at!(
        Invalid,
        drand_verify::verify(&pk, curr.round as u64, &sign, &psign)
    )?)
}
