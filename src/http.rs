use serde::Deserialize;

use std::{
    cmp,
    convert::{TryFrom, TryInto},
    time,
};

use crate::{endpoints::State, verify, Error, Info, Random, Result};

pub(crate) const MAX_ELAPSED_WINDOW: usize = 32;

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
                let avg = cmp::min($this.to_elapsed() * 2, MAX_ELAPSED);
                $this.add_elapsed(avg);
            }
        }
        res
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

    pub(crate) fn to_elapsed(&self) -> time::Duration {
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

    pub(crate) async fn boot_phase1(
        &mut self,
        rot: Option<&[u8]>,
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<(Info, Random)> {
        let endpoint = self.to_base_url();
        let client = new_http_client(agent.clone())?;

        // get info
        let info: Info = {
            let resp = err_at!(
                IOError,
                async_get!(self, client, make_url!("info", endpoint))
            )?;
            let info: InfoJson = err_at!(JsonParse, resp.json().await)?;
            info.try_into()?
        };

        // confirm whether root-of-trust is as expected.
        match rot {
            Some(rot) if rot != info.hash => {
                let msg = format!("not expected drand-group");
                err_at!(NotSecure, msg: msg)?
            }
            _ => (),
        }

        // get latest round
        let latest = self.do_get(&client, None).await?;

        Ok((info, latest))
    }

    pub(crate) async fn boot_phase2(
        &mut self,
        mut state: State,
        latest: Random,
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<State> {
        let client = new_http_client(agent.clone())?;

        // get check_point
        state.check_point = match (state.determinism, state.check_point.take()) {
            // continued-determinism
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point, latest);
                    self.verify(&state, from, till, agent.clone()).await?
                };
                Some(check_point)
            }
            // reestablish-determinism
            (true, None) => {
                let r = self.do_get(&client, Some(1)).await?;
                Some(self.verify(&state, r, latest, agent.clone()).await?)
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
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<(State, Random)> {
        let client = new_http_client(agent.clone())?;

        let r = self.do_get(&client, round).await?;

        let (check_point, r) = match (state.check_point.take(), round) {
            // just return an earlier random-ness.
            (Some(check_point), Some(round)) if round <= check_point.round => {
                // TODO: with cache we can optimize this call
                (check_point, r)
            }
            // return a verified randomness, requested round
            (Some(check_point), Some(_)) if state.secure => {
                let r = self.verify(&state, check_point, r, agent.clone()).await?;
                (r.clone(), r)
            }
            // return insecure randomness, requested round
            (Some(_), Some(_)) => (r.clone(), r),
            // return a verified randomness, latest round
            (Some(check_point), None) if state.secure => {
                let r = self.verify(&state, check_point, r, agent.clone()).await?;
                (r.clone(), r)
            }
            // return insecure randomness, latest round
            (Some(_), None) => (r.clone(), r),
            // return unverified and insecure randomness
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
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<Random> {
        let client = new_http_client(agent.clone())?;

        let mut iter = latest.round..till.round;
        let pk = state.info.public_key.as_slice();
        latest = loop {
            latest = match iter.next() {
                Some(round) if round == latest.round => continue,
                Some(round) => {
                    let ps = &latest.previous_signature;
                    let r = self.do_get(&client, Some(round)).await?;
                    if !verify::verify_chain(&pk, &ps, &r)? {
                        err_at!(NotSecure, msg: format!("fail verify {}", r))?;
                    };
                    r
                }
                None => {
                    let ps = &latest.previous_signature;
                    if !verify::verify_chain(&pk, &ps, &till)? {
                        err_at!(NotSecure, msg: format!("fail verify {}", till))?;
                    }
                    break till;
                }
            };
        };

        Ok(latest)
    }

    pub(crate) async fn do_get(
        &mut self,
        client: &reqwest::Client,
        round: Option<u128>,
    ) -> Result<Random> {
        let endpoint = self.to_base_url();

        let r = match round {
            Some(round) => {
                let resp = {
                    let url = make_url!("public", endpoint, round);
                    err_at!(IOError, async_get!(self, client, url))?
                };
                let r: RandomJson = err_at!(JsonParse, resp.json().await)?;
                r.try_into()?
            }
            None => {
                let resp = {
                    let url = make_url!("public", endpoint);
                    err_at!(IOError, async_get!(self, client, url))?
                };
                let r: RandomJson = err_at!(JsonParse, resp.json().await)?;
                r.try_into()?
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
    #[serde(alias = "groupHash")] // TODO: ask this to drand/drand community.
    group_hash: String,
}

impl TryFrom<InfoJson> for Info {
    type Error = Error;

    fn try_from(val: InfoJson) -> Result<Self> {
        let genesis_time = time::Duration::from_secs(val.genesis_time);
        let val = Info {
            public_key: err_at!(HexParse, hex::decode(&val.public_key))?,
            period: time::Duration::from_secs(val.period),
            genesis_time: time::UNIX_EPOCH + genesis_time,
            hash: err_at!(HexParse, hex::decode(&val.hash))?,
            group_hash: err_at!(HexParse, hex::decode(&val.group_hash))?,
        };

        Ok(val)
    }
}

#[derive(Deserialize)]
struct RandomJson {
    round: u128,
    randomness: String,
    signature: String,
    previous_signature: String,
}

impl TryFrom<RandomJson> for Random {
    type Error = Error;

    fn try_from(val: RandomJson) -> Result<Self> {
        let psign = err_at!(HexParse, hex::decode(&val.previous_signature))?;
        let val = Random {
            round: val.round,
            randomness: err_at!(HexParse, hex::decode(&val.randomness))?,
            signature: err_at!(HexParse, hex::decode(&val.signature))?,
            previous_signature: psign,
        };

        Ok(val)
    }
}

fn new_http_client(agent: Option<reqwest::header::HeaderValue>) -> Result<reqwest::Client> {
    let b = reqwest::Client::builder();
    let b = match agent {
        Some(agent) => b.user_agent(agent),
        None => b,
    };
    err_at!(Invalid, b.build(), format!("http builder"))
}

#[cfg(test)]
#[path = "http_test.rs"]
mod http_test;
