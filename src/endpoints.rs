use sha2::{Digest, Sha256};

use std::{fmt, result, time};

use crate::{Config, Result, Round};

/// Endpoint is an enumeration of several known http endpoint from
/// main-net.
pub struct Endpoints {
    endpoints: Vec<Endpoint>,
}

enum Endpoint {
    Http(State),
}

impl<R> From<Config<R>> for State
where
    R: Round,
{
    fn from(mut cfg: Config<R>) -> Self {
        State {
            info: Info::default(),
            check_point: cfg.check_point.take().map(Random::from_round),
            determinism: cfg.determinism,
            secure: cfg.secure,
            rate_limit: cfg.rate_limit,
            elapsed: Vec::default(),
        }
    }
}

impl Endpoint {
    pub fn new_drand_api<R: Round>(cfg: Config<R>) -> Self {
        Endpoint::Http(cfg.into())
    }

    //pub fn boot(&mut self) -> impl Future<Output = Result<()>> {
    //    match &self.inner {
    //        Inner::Http(state) => state.boot("https://api.drand.sh"),
    //    }
    //}
}

// State of each endpoint. An endpoint is booted and subsequently
// used to watch/get future rounds of random-ness.
pub(crate) struct State {
    pub(crate) info: Info,
    pub(crate) check_point: Option<Random>,
    pub(crate) determinism: bool,
    pub(crate) secure: bool,
    pub(crate) rate_limit: usize,
    pub(crate) elapsed: Vec<time::Duration>,
}

// Info is from main-net's `/info` endpoint.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Info {
    pub(crate) public_key: Vec<u8>,
    pub(crate) period: time::Duration,
    pub(crate) genesis_time: time::SystemTime,
    pub(crate) hash: Vec<u8>,
}

impl Default for Info {
    fn default() -> Self {
        Info {
            public_key: Vec::default(),
            period: time::Duration::default(),
            genesis_time: time::UNIX_EPOCH,
            hash: Vec::default(),
        }
    }
}

// Random is main-net's `/public/latest` and `/public/{round}` endpoints.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Random {
    pub(crate) round: u128,
    pub(crate) randomness: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) previous_signature: Vec<u8>,
}

impl fmt::Display for Random {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "Random<{}>", self.round)
    }
}

impl Round for Random {
    #[inline]
    fn to_round(&self) -> u128 {
        self.round
    }

    #[inline]
    fn as_randomness(&self) -> &[u8] {
        self.randomness.as_slice()
    }

    #[inline]
    fn as_signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    #[inline]
    fn as_previous_signature(&self) -> Option<&[u8]> {
        Some(self.previous_signature.as_slice())
    }

    fn to_digest(&self) -> Result<Vec<u8>> {
        let mut hasher = Sha256::default();
        hasher.update(&self.previous_signature);
        hasher.update(self.round.to_be_bytes());
        Ok(hasher.finalize().to_vec())
    }
}

impl Random {
    pub(crate) fn from_round<R: Round>(r: R) -> Self {
        let previous_signature = match r.as_previous_signature() {
            Some(bytes) => bytes.to_vec(),
            None => vec![],
        };
        Random {
            round: r.to_round(),
            randomness: r.as_randomness().to_vec(),
            signature: r.as_signature().to_vec(),
            previous_signature,
        }
    }
}
