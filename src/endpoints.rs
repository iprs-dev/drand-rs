use serde::Deserialize;
use sha2::{Digest, Sha256};

use std::{fmt, time, result};

use crate::{Config, Error, Result, Round};

macro_rules! make_url {
    ("info", $ep:expr) => {
        $ep.to_string() + "/info"
    };
    ("public", $ep:expr) => {
        $ep.to_string() + "/public/latest"
    };
    ("public", $ep:expr, $r:expr) => {
        $ep.to_string() + "/public/" + &($r.to_string())
    };
}

/// Endpoint is an enumeration of several known http endpoint from
/// main-net.
pub struct Endpoint {
    inner: Inner,
}

enum Inner {
    DrandApi(State),
}

impl<R> From<Config<R>> for State
where
    R: Round,
{
    fn from(mut cfg: Config<R>) -> Self {
        State {
            info: None,
            check_point: cfg.check_point.take().map(Random::from_round),
            determinism: cfg.determinism,
            secure: cfg.secure,
            rate_limit: cfg.rate_limit,
        }
    }
}

impl Endpoint {
    pub fn new_drand_api<R: Round>(cfg: Config<R>) -> Result<Self> {
        let inner = Inner::DrandApi(cfg.into());
        Ok(Endpoint { inner })
    }

    //pub fn boot(&mut self) -> impl Future<Output = Result<()>> {
    //    match &self.inner {
    //        Inner::DrandApi(state) => state.boot("https://api.drand.sh"),
    //    }
    //}
}

// State of each endpoint. An endpoint is booted and subsequently
// used to watch/get future rounds of random-ness.
struct State {
    info: Option<Info>,
    check_point: Option<Random>,
    determinism: bool,
    secure: bool,
    rate_limit: usize,
}

impl State {
    async fn boot(&mut self, endpoint: &str) -> Result<()> {
        let client = reqwest::Client::new();

        // get info
        let info: Info = {
            let response = {
                let val = client.get(&make_url!("info", endpoint));
                err_at!(IOError, val.send().await)?
            };
            let info: InfoJson = err_at!(Parse, response.json().await)?;
            info.into()
        };
        self.info = Some(info.clone());

        // get latest round
        let latest: Random = {
            let response = {
                let val = client.get(&make_url!("public", endpoint));
                err_at!(IOError, val.send().await)?
            };
            let r: RandomJson = err_at!(Parse, response.json().await)?;
            r.into()
        };

        // get check_point
        self.check_point = match (self.determinism, self.check_point.take()) {
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point.round, latest.round);
                    Self::verify(&client, &info, endpoint, from, till).await?
                };
                Some(check_point)
            }
            (true, None) => {
                let response = {
                    let val = client.get(&make_url!("public", endpoint, 1));
                    err_at!(IOError, val.send().await)?
                };
                let r: Random = {
                    let r: RandomJson = err_at!(Parse, response.json().await)?;
                    r.into()
                };
                let check_point = {
                    let (from, till) = (r.round, latest.round);
                    Self::verify(&client, &info, endpoint, from, till).await?
                };
                Some(check_point)
            }
            (false, _) if self.secure => Some(latest),
            (false, _) => None,
        };

        Ok(())
    }

    async fn verify(
        client: &reqwest::Client,
        info: &Info,
        endpoint: &str,
        from: u128,
        till: u128,
    ) -> Result<Random> {
        use std::str::from_utf8;

        for round in (from..till).map(|r| r + 1) {
            let r: Random = {
                let response = {
                    let val = client.get(&make_url!("public", endpoint, round));
                    err_at!(IOError, val.send().await)?
                };
                let r: RandomJson = err_at!(Parse, response.json().await)?;
                r.into()
            };
            let psign = match r.previous_signature.as_ref() {
                Some(psign) => psign,
                None => err_at!(Invalid, msg: format!("missing prev-signature"))?,
            };

            let pk = {
                let s = err_at!(Parse, from_utf8(&info.public_key))?;
                let mut bytes: [u8; 48] = [0_u8; 48];
                bytes[..].clone_from_slice(&err_at!(Parse, hex::decode(&s))?);
                err_at!(Parse, drand_verify::g1_from_fixed(bytes))?
            };
            let res = {
                let psign = err_at!(Parse, hex::decode(&psign))?;
                let sign = err_at!(Parse, hex::decode(&r.signature))?;
                err_at!(Invalid, drand_verify::verify(
                    &pk,
                    round as u64,
                    &sign,
                    &psign,
                ))?
            };
            match res {
                true => (),
                false => err_at!(Invalid, msg: format!("fail verify {}", r))?,
            };
        }

        let latest: Random = {
            let response = {
                let val = client.get(&make_url!("public", endpoint, till));
                err_at!(IOError, val.send().await)?
            };
            let r: RandomJson = err_at!(Parse, response.json().await)?;
            r.into()
        };

        Ok(latest)
    }
}

#[derive(Deserialize)]
struct InfoJson {
    public_key: String,
    period: u64,
    genesis_time: u64,
    hash: String,
}

// Info is from main-net's `/info` endpoint.
#[derive(Clone, Eq, PartialEq)]
struct Info {
    public_key: Vec<u8>,
    period: time::Duration,
    genesis_time: time::SystemTime,
    hash: Vec<u8>,
}

impl From<InfoJson> for Info {
    fn from(val: InfoJson) -> Self {
        let genesis_time = time::Duration::from_secs(val.genesis_time);
        Info {
            public_key: val.public_key.as_bytes().to_vec(),
            period: time::Duration::from_secs(val.period),
            genesis_time: time::UNIX_EPOCH + genesis_time,
            hash: val.hash.as_bytes().to_vec(),
        }
    }
}

#[derive(Deserialize)]
struct RandomJson {
    round: u128,
    randomness: String,
    signature: String,
    previous_signature: String,
}

// Random is main-net's `/public/latest` and `/public/{round}` endpoints.
#[derive(Clone, Eq, PartialEq)]
struct Random {
    round: u128,
    randomness: Vec<u8>,
    signature: Vec<u8>,
    previous_signature: Option<Vec<u8>>,
}

impl From<RandomJson> for Random {
    fn from(val: RandomJson) -> Self {
        Random {
            round: val.round,
            randomness: val.randomness.as_bytes().to_vec(),
            signature: val.signature.as_bytes().to_vec(),
            previous_signature: Some(val.previous_signature.as_bytes().to_vec()),
        }
    }
}

impl fmt::Display for Random {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "Random<{}>", self.round)
    }
}

impl Round for Random {
    fn to_round(&self) -> u128 {
        self.round
    }

    fn as_randomness(&self) -> &[u8] {
        self.randomness.as_slice()
    }

    fn as_signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    fn as_pervious_signature(&self) -> Option<&[u8]> {
        self.previous_signature.as_ref().map(|x| x.as_slice())
    }

    fn to_digest(&self) -> Result<Vec<u8>> {
        let mut hasher = Sha256::default();
        match &self.previous_signature {
            Some(ps) => hasher.update(ps),
            None => err_at!(Fatal, msg: format!("missing previous signature"))?,
        }
        hasher.update(self.round.to_be_bytes());
        Ok(hasher.finalize().to_vec())
    }
}

impl Random {
    fn from_round<R: Round>(r: R) -> Self {
        Random {
            round: r.to_round(),
            randomness: r.as_randomness().to_vec(),
            signature: r.as_signature().to_vec(),
            previous_signature: r.as_pervious_signature().map(|x| x.to_vec()),
        }
    }
}

