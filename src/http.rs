use serde::Deserialize;

use std::{
    cmp,
    convert::{TryFrom, TryInto},
    time,
};

use crate::{core::MAX_CONNS, endpoints::State, verify, Error, Info, Random, Result};

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
    ($client:ident, $url:expr) => {{
        let start = time::Instant::now();
        let res = $client.get($url.as_str()).send().await;
        (res, start.elapsed())
    }};
}

macro_rules! add_elapsed {
    ($this:ident, $res:expr, $elapsed:expr) => {{
        match $res {
            Ok(val) => {
                $this.add_elapsed($elapsed);
                Ok(val)
            }
            err @ Err(_) => {
                let elapsed = cmp::min($this.to_elapsed() * 2, MAX_ELAPSED);
                $this.add_elapsed(elapsed);
                err
            }
        }
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
        es.push(elapsed);
    }

    pub(crate) async fn boot_phase1(
        &mut self,
        rot: Option<&[u8]>,
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<(Info, Random)> {
        let endpoint = self.to_base_url();
        let client = new_http_client(MAX_CONNS, agent.clone())?;

        // get info
        let info: Info = {
            let (res, elapsed) = {
                let url = make_url!("info", endpoint);
                async_get!(client, url)
            };
            let resp = err_at!(IOError, add_elapsed!(self, res, elapsed))?;
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
        let client = new_http_client(MAX_CONNS, agent.clone())?;

        // get check_point
        state.check_point = match (state.determinism, state.check_point.take()) {
            // reestablish-determinism
            (true, None) => {
                let r = self.do_get(&client, Some(1)).await?;
                Some(self.verify(&state, r, latest, agent.clone()).await?)
            }
            // continued-determinism
            (true, Some(check_point)) => {
                let check_point = {
                    let (from, till) = (check_point, latest);
                    self.verify(&state, from, till, agent.clone()).await?
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
        &mut self,
        mut state: State,
        round: Option<u128>,
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<(State, Random)> {
        let client = new_http_client(MAX_CONNS, agent.clone())?;

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
        mut prev: Random,
        till: Random,
        agent: Option<reqwest::header::HeaderValue>,
    ) -> Result<Random> {
        let endpoint = self.to_base_url();
        let client = new_http_client(state.max_conns, agent.clone())?;
        let pk = state.info.public_key.as_slice();

        while prev.round < till.round {
            let till_round = cmp::min(prev.round + 1000, till.round);

            let mut rounds = vec![];
            for round in (prev.round + 1)..till_round {
                let url = make_url!("public", endpoint, round);
                let client = &client;
                rounds.push(async move {
                    let (res, elapsed) = { async_get!(client, url) };
                    let resp = err_at!(IOError, res)?;
                    let r: RandomJson = err_at!(JsonParse, resp.json().await)?;
                    let r: Random = r.try_into()?;
                    Ok::<(Random, time::Duration), Error>((r, elapsed))
                });
            }

            let mut err = false;
            for item in futures::future::join_all(rounds).await {
                let random = match item {
                    Ok((_, elapsed)) if err => {
                        self.add_elapsed(elapsed);
                        continue;
                    }
                    Ok((r, elapsed)) => {
                        self.add_elapsed(elapsed);
                        r
                    }
                    Err(_) => {
                        let elapsed = cmp::min(self.to_elapsed() * 2, MAX_ELAPSED);
                        self.add_elapsed(elapsed);
                        err = true;
                        continue;
                    }
                };
                if !verify::verify_chain(&pk, &prev.signature, &random)? {
                    err_at!(NotSecure, msg: format!("fail verify {}", random))?;
                }
                prev = random;
            }
        }

        Ok(till)
    }

    pub(crate) async fn do_get(
        &mut self,
        client: &reqwest::Client,
        round: Option<u128>,
    ) -> Result<Random> {
        let endpoint = self.to_base_url();

        let r = match round {
            Some(round) => {
                let (res, elapsed) = {
                    let url = make_url!("public", endpoint, round);
                    async_get!(client, url)
                };
                let resp = err_at!(IOError, add_elapsed!(self, res, elapsed))?;
                let r: RandomJson = err_at!(JsonParse, resp.json().await)?;
                r.try_into()?
            }
            None => {
                let (res, elapsed) = {
                    let url = make_url!("public", endpoint);
                    async_get!(client, url)
                };
                let resp = err_at!(IOError, add_elapsed!(self, res, elapsed))?;
                let r: RandomJson = err_at!(JsonParse, resp.json().await)?;
                r.try_into()?
            }
        };

        Ok(r)
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

fn new_http_client(
    max: usize,
    agent: Option<reqwest::header::HeaderValue>,
) -> Result<reqwest::Client> {
    let b = reqwest::Client::builder().pool_max_idle_per_host(max);
    let b = match agent {
        Some(agent) => b.user_agent(agent),
        None => b,
    };
    err_at!(Invalid, b.build(), format!("http builder"))
}

#[cfg(test)]
#[path = "http_test.rs"]
mod http_test;
