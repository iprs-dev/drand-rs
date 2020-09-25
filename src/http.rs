use serde::Deserialize;

use std::time;

use crate::{
    endpoints::{Info, Random, State},
    util, Error, Result,
};

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
            // continued-determinism
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point, latest);
                    self.verify(&client, &state, from, till).await?
                };
                Some(check_point)
            }
            // reestablish-determinsm
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
                    let (from, till) = (r, latest);
                    self.verify(&client, &state, from, till).await?
                };
                Some(check_point)
            }
            // assumed-determinism
            (false, _) if state.secure => Some(latest),
            // no-determinism
            (false, _) => None,
        };

        Ok(state)
    }

    pub(crate) async fn get(
        &self,
        mut state: State,
        round: Option<u128>,
    ) -> Result<(State, Random)> {
        let client = reqwest::Client::new();

        let r = match self.do_get(&client, round).await {
            Ok(r) => Ok(r),
            err @ Err(_) if round.is_none() => err,
            Err(err) => {
                let r = self.do_get(&client, None).await?;
                let round = round.unwrap_or(0);
                if round <= r.round {
                    let msg = format!("get failed for {} {}", round, err);
                    err_at!(Invalid, msg: msg)
                } else {
                    Ok(r)
                }
            }
        }?;

        let (check_point, r) = match (state.check_point.take(), round) {
            (Some(check_point), Some(round)) if round <= check_point.round => {
                // just return an earlier random-ness.
                // TODO: with cache we can optimize this call
                (check_point, r)
            }
            (Some(check_point), Some(_)) if state.secure => {
                let r = self.verify(&client, &state, check_point, r).await?;
                (r.clone(), r)
            }
            (Some(check_point), Some(_)) => (r.clone(), r),
            (Some(check_point), None) if state.secure => {
                let r = self.verify(&client, &state, check_point, r).await?;
                (r.clone(), r)
            }
            (Some(check_point), None) => (r.clone(), r),
            (None, _) => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        state.check_point = Some(check_point);

        Ok((state, r))
    }

    async fn verify(
        &self,
        client: &reqwest::Client,
        state: &State,
        mut latest: Random,
        till: Random,
    ) -> Result<Random> {
        let mut iter = latest.round..till.round;
        let pk = state.info.public_key.as_slice();
        loop {
            match iter.next() {
                Some(round) if round == latest.round => continue,
                Some(round) => {
                    let r = self.do_get(client, Some(round)).await?;
                    if !util::verify_chain(&pk, &latest, &r)? {
                        err_at!(Invalid, msg: format!("fail verify {}", r))?;
                    };
                    latest = r;
                }
                None => {
                    if !util::verify_chain(&pk, &latest, &till)? {
                        err_at!(Invalid, msg: format!("fail verify {}", till))?;
                    }
                    latest = till;
                    break;
                }
            }
        }

        Ok(latest)
    }

    async fn do_get(&self, client: &reqwest::Client, round: Option<u128>) -> Result<Random> {
        let endpoint = self.to_base_url();

        let r = match round {
            Some(round) => {
                let response = {
                    let val = client.get(&make_url!("public", endpoint, round));
                    err_at!(IOError, val.send().await)?
                };
                let r: RandomJson = err_at!(Parse, response.json().await)?;
                r.into()
            }
            None => {
                let response = {
                    let val = client.get(&make_url!("public", endpoint));
                    err_at!(IOError, val.send().await)?
                };
                let r: RandomJson = err_at!(Parse, response.json().await)?;
                r.into()
            }
        };

        Ok(r)
    }

    fn to_base_url(&self) -> String {
        match self {
            Http::DrandApi => "https://api.drand.sh".to_string(),
        }
    }
}

#[derive(Deserialize)]
struct InfoJson {
    public_key: String,
    period: u64,
    genesis_time: u64,
    hash: String,
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
