use std::fmt;

use crate::{Error, Result, Round};

/// Short form to compose Error values.
///
/// Here are few possible ways:
///
/// ```ignore
/// use crate::Error;
/// err_at!(Error::Invalid(String::default(), "bad argument"));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, msg: format!("bad argument"));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, std::io::read(buf));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, std::fs::read(file_path), format!("read failed"));
/// ```
///
#[macro_export]
macro_rules! err_at {
    ($e:expr) => {{
        use Error::*;

        let p = format!("{}:{}", file!(), line!());
        match $e {
            Ok(val) => Ok(val),
            Err(Fatal(_, s)) => Err(Fatal(p, s)),
            Err(Invalid(_, s)) => Err(Invalid(p, s)),
            Err(IOError(_, s)) => Err(IOError(p, s)),
            Err(Parse(_, s)) => Err(Parse(p, s)),
        }
    }};
    ($v:ident, msg:$m:expr) => {{
        let prefix = format!("{}:{}", file!(), line!());
        Err(Error::$v(prefix, format!("{}", $m)))
    }};
    ($v:ident, $e:expr) => {
        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                Err(Error::$v(prefix, format!("{}", err)))
            }
        }
    };
    ($v:ident, $e:expr, $m:expr) => {
        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                Err(Error::$v(prefix, format!("{} {}", $m, err)))
            }
        }
    };
}

pub(crate) fn verify_chain<R>(pk: &[u8], prev: &R, curr: &R) -> Result<bool>
where
    R: Round + fmt::Display,
{
    use std::str::from_utf8;

    let round = curr.to_round();

    let psign = match curr.as_previous_signature() {
        Some(psign) => psign,
        None => {
            let msg = format!("missing previous signature {}", round);
            err_at!(Invalid, msg: msg)?
        }
    };
    if prev.as_signature() != psign {
        let (s, p) = (prev.as_signature(), psign);
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
    let sign = err_at!(Parse, hex::decode(curr.as_signature()))?;
    Ok(err_at!(
        Invalid,
        drand_verify::verify(&pk, round as u64, &sign, &psign)
    )?)
}
