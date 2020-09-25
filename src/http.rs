use serde::Deserialize;

use std::{cmp, time};

use crate::{
    endpoints::{Info, Random, State},
    util, Error, Result,
};

const MAX_ELAPSED_WINDOW: usize = 32;
pub(crate) const MAX_ELAPSED: time::Duration = time::Duration::from_secs(3600 * 24);

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

macro_rules! async_get {
    ($this:ident, $client:ident, $url:expr) => {{
        let start = time::Instant::now();
        let res = $client.get($url.as_str()).send().await;
        match res {
            Ok(_) => {
                $this.add_elapsed(start.elapsed());
            }
            Err(_) => {
                let avg = cmp::min($this.avg_elapsed() * 2, MAX_ELAPSED);
                $this.add_elapsed(avg);
            }
        }
        err_at!(IOError, res)
    }};
}

#[derive(Clone)]
pub(crate) enum Http {
    DrandApi(Vec<time::Duration>),
}

impl Http {
    pub(crate) fn new_drand_api() -> Http {
        Http::DrandApi(Vec::default())
    }

    pub(crate) fn avg_elapsed(&self) -> time::Duration {
        let es = match self {
            Http::DrandApi(es) => es,
        };
        match es.len() {
            0 => time::Duration::from_secs(u64::MAX),
            n => {
                let sum: time::Duration = es.iter().sum();
                sum / (n as u32)
            }
        }
    }

    pub(crate) async fn boot_phase1(&mut self) -> Result<(Info, Random)> {
        let endpoint = self.to_base_url();
        let client = reqwest::Client::new();

        // get info
        let info = {
            let resp = async_get!(self, client, make_url!("info", endpoint))?;
            let info: InfoJson = err_at!(Parse, resp.json().await)?;
            info.into()
        };

        // get latest round
        let latest = self.do_get(&client, None).await?;

        Ok((info, latest))
    }

    pub(crate) async fn boot_phase2(&mut self, mut state: State, latest: Random) -> Result<State> {
        let client = reqwest::Client::new();

        // get check_point
        state.check_point = match (state.determinism, state.check_point.take()) {
            // continued-determinism
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point, latest);
                    self.verify(&state, from, till).await?
                };
                Some(check_point)
            }
            // reestablish-determinsm
            (true, None) => {
                let r = self.do_get(&client, Some(1)).await?;
                Some(self.verify(&state, r, latest).await?)
            }
            // assumed-determinism
            (false, _) if state.secure => Some(latest),
            // no-determinism
            (false, _) => None,
        };

        Ok(state)
    }

    pub(crate) async fn get(
        &mut self,
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
                let r = self.verify(&state, check_point, r).await?;
                (r.clone(), r)
            }
            (Some(_), Some(_)) => (r.clone(), r),
            (Some(check_point), None) if state.secure => {
                let r = self.verify(&state, check_point, r).await?;
                (r.clone(), r)
            }
            (Some(_), None) => (r.clone(), r),
            (None, _) => (r.clone(), r),
        };
        state.check_point = Some(check_point);

        Ok((state, r))
    }

    pub(crate) async fn verify(
        &mut self,
        state: &State,
        mut latest: Random,
        till: Random,
    ) -> Result<Random> {
        let client = reqwest::Client::new();

        let mut iter = latest.round..till.round;
        let pk = state.info.public_key.as_slice();
        loop {
            match iter.next() {
                Some(round) if round == latest.round => continue,
                Some(round) => {
                    let r = self.do_get(&client, Some(round)).await?;
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

    async fn do_get(&mut self, client: &reqwest::Client, round: Option<u128>) -> Result<Random> {
        let endpoint = self.to_base_url();

        let r = match round {
            Some(round) => {
                let resp = {
                    let url = make_url!("public", endpoint, round);
                    async_get!(self, client, url)?
                };
                let r: RandomJson = err_at!(Parse, resp.json().await)?;
                r.into()
            }
            None => {
                let resp = {
                    let url = make_url!("public", endpoint);
                    async_get!(self, client, url)?
                };
                let r: RandomJson = err_at!(Parse, resp.json().await)?;
                r.into()
            }
        };

        Ok(r)
    }

    fn to_base_url(&self) -> String {
        match self {
            Http::DrandApi(_) => "https://api.drand.sh".to_string(),
        }
    }

    fn add_elapsed(&mut self, elapsed: time::Duration) {
        let es = match self {
            Http::DrandApi(es) => es,
        };

        match es.len() {
            n if n >= MAX_ELAPSED_WINDOW => {
                es.remove(0);
            }
            _ => (),
        };
        es.push(elapsed)
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
