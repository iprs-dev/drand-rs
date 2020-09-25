use serde::Deserialize;
use sha2::{Digest, Sha256};

use std::{fmt, result, time};

use crate::{endpoints::State, util, Error, Result, Round};

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

pub(crate) enum Http {
    DrandApi,
}

impl Http {
    pub(crate) fn to_base_url(&self) -> String {
        match self {
            Http::DrandApi => "https://api.drand.sh".to_string(),
        }
    }

    pub(crate) async fn boot(&self, mut state: State) -> Result<State> {
        let endpoint = self.to_base_url();
        let client = reqwest::Client::new();

        // get info
        state.info = {
            let response = {
                let val = client.get(&make_url!("info", endpoint));
                err_at!(IOError, val.send().await)?
            };
            let info: InfoJson = err_at!(Parse, response.json().await)?;
            info.into()
        };

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
        state.check_point = match (state.determinism, state.check_point.take()) {
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point, latest.round);
                    Self::verify(&client, &state, &endpoint, from, till).await?
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
                    let (from, till) = (r, latest.round);
                    Self::verify(&client, &state, &endpoint, from, till).await?
                };
                Some(check_point)
            }
            (false, _) if state.secure => Some(latest),
            (false, _) => None,
        };

        Ok(state)
    }

    async fn verify(
        client: &reqwest::Client,
        state: &State,
        endpoint: &str,
        mut latest: Random,
        till: u128,
    ) -> Result<Random> {
        for round in (latest.round..till).map(|r| r + 1) {
            let r: Random = {
                let response = {
                    let val = client.get(&make_url!("public", endpoint, round));
                    err_at!(IOError, val.send().await)?
                };
                let r: RandomJson = err_at!(Parse, response.json().await)?;
                r.into()
            };

            match util::verify_chain(&state.info.public_key, &latest, &r)? {
                true => (),
                false => err_at!(Invalid, msg: format!("fail verify {}", r))?,
            };

            latest = r;
        }

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
pub(crate) struct Info {
    public_key: Vec<u8>,
    period: time::Duration,
    genesis_time: time::SystemTime,
    hash: Vec<u8>,
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
pub(crate) struct Random {
    round: u128,
    randomness: Vec<u8>,
    signature: Vec<u8>,
    previous_signature: Vec<u8>,
}

impl From<RandomJson> for Random {
    fn from(val: RandomJson) -> Self {
        Random {
            round: val.round,
            randomness: val.randomness.as_bytes().to_vec(),
            signature: val.signature.as_bytes().to_vec(),
            previous_signature: val.previous_signature.as_bytes().to_vec(),
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
