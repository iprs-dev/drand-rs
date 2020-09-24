use groupy::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};
use hex;
use paired::{
    bls12_381::{Bls12, Fq12, G1Affine, G1Compressed, G2Affine, G2Compressed, G2},
    Engine, ExpandMsgXmd, Field, HashToCurve, PairingCurveAffine,
};
use sha2::Sha256;

use crate::{Error, Info, Result, Round};

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Verify checks beacon components to see if they are valid.
pub(crate) fn verify<I: Info, R: Round>(info: &I, r: &R) -> Result<bool> {
    use std::str::from_utf8;

    let pk = {
        let s = err_at!(Parse, from_utf8(info.as_public_key()))?;
        let pk = err_at!(Parse, hex::decode(s))?;
        g1_from_bytes(pk)?
    };
    let g1 = G1Affine::one();
    let sigma = err_at!(Fatal, g2_from_bytes(r.as_signature()))?;
    let msg_on_g2 = {
        let digest = r.to_digest()?;
        let g = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&digest, DOMAIN);
        g.into_affine()
    };

    Ok(fast_pairing_equality(&g1, &sigma, &pk, &msg_on_g2))
}

/// Checks if e(p, q) == e(r, s)
///
/// See https://hackmd.io/@benjaminion/bls12-381#Final-exponentiation
fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    let e_prime = |p: &G1Affine, q: &G2Affine| -> Fq12 {
        Bls12::miller_loop([(&(p.prepare()), &(q.prepare()))].iter())
    };

    let minus_p = {
        let mut out = *p;
        out.negate();
        out
    };

    let mut tmp = e_prime(&minus_p, &q);
    tmp.mul_assign(&e_prime(r, &s));
    match Bls12::final_exponentiation(&tmp) {
        Some(value) => value == Fq12::one(),
        None => false,
    }
}

fn g1_from_bytes(data: Vec<u8>) -> Result<G1Affine> {
    match data.len() {
        48 => {
            let mut bytes: [u8; 48] = [0_u8; 48];
            bytes[..].clone_from_slice(&data);
            G1Compressed(bytes);
            err_at!(Invalid, G1Compressed(bytes).into_affine())
        }
        n => err_at!(Invalid, msg: format!("invalid len {}", n)),
    }
}

fn g2_from_bytes(data: &[u8]) -> Result<G2Affine> {
    match data.len() {
        96 => {
            let mut bytes = [0_u8; 96];
            bytes[..].clone_from_slice(&data[..]);
            err_at!(Invalid, G2Compressed(bytes).into_affine())
        }
        n => err_at!(Invalid, msg: format!("invalid len {}", n)),
    }
}
