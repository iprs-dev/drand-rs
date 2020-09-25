use sha2::{Digest, Sha256};

use std::{fmt, result, time};

use crate::{http::Http, Config, Error, Result, Round};

pub enum Endpoint {
    HttpDrandApi,
    HttpDrandApi2,
    HttpDrandApi3,
    HttpCloudflare,
}

// Endpoints is an enumeration of several known http endpoint from
// main-net.
pub struct Endpoints {
    state: State,
    endpoints: Vec<Inner>,
}

impl Endpoints {
    pub(crate) fn new<R: Round>(cfg: Config<R>) -> Self {
        Endpoints {
            state: cfg.into(),
            endpoints: Vec::default(),
        }
    }

    pub(crate) fn add_endpoint(&mut self, endp: Endpoint) -> &mut Self {
        let endp = match endp {
            Endpoint::HttpDrandApi => Inner::Http(Http::new_drand_api()),
            Endpoint::HttpDrandApi2 => Inner::Http(Http::new_drand_api()),
            Endpoint::HttpDrandApi3 => Inner::Http(Http::new_drand_api()),
            Endpoint::HttpCloudflare => Inner::Http(Http::new_drand_api()),
        };
        self.endpoints.push(endp);
        self
    }

    pub(crate) async fn boot(&mut self) -> Result<()> {
        let (info, latest) = match self.endpoints.len() {
            0 => err_at!(Invalid, msg: format!("initialize endpoint"))?,
            1 => self.endpoints[0].boot_phase1().await?,
            _ => {
                let (info, latest) = self.endpoints[0].boot_phase1().await?;

                let mut tail = vec![];
                for mut endp in self.endpoints[1..].to_vec() {
                    let (info1, latest1) = (info.clone(), latest.clone());
                    tail.push(async {
                        let (info2, _) = endp.boot_phase1().await?;

                        Self::boot_validate_info(info1, info2)?;

                        let s = {
                            let mut s = State::default();
                            s.check_point = None;
                            s.secure = false;
                            s
                        };
                        let (_, r) = endp.get(s, Some(latest1.round)).await?;
                        Self::boot_validate_latest(latest1, r)?;
                        Ok::<Inner, Error>(endp)
                    })
                }

                futures::future::join_all(tail).await;

                (info, latest)
            }
        };

        self.state.info = info;
        self.state = {
            let s = self.state.clone();
            self.endpoints[0].boot_phase2(s, latest).await?
        };

        Ok(())
    }

    pub(crate) async fn get(&mut self, round: Option<u128>) -> Result<Random> {
        let (state, r) = loop {
            match self.get_endpoint_pair() {
                (Some(mut e1), Some(mut e2)) => {
                    let (res1, res2) = futures::join!(
                        e1.get(self.state.clone(), round),
                        e2.get(self.state.clone(), round),
                    );
                    match (res1, res2) {
                        (Ok((s1, r1)), Ok((s2, r2))) => {
                            if r1.round > r2.round {
                                break (s1, r1);
                            } else {
                                break (s2, r2);
                            };
                        }
                        (Ok((s1, r1)), Err(_)) => break (s1, r1),
                        (Err(_), Ok((s2, r2))) => break (s2, r2),
                        (Err(_), Err(_)) => (),
                    };
                }
                (Some(mut e1), None) => {
                    let (state, r) = e1.get(self.state.clone(), round).await?;
                    break (state, r);
                }
                (None, _) => {
                    let msg = format!("missing/exhausted endpoint");
                    err_at!(Fatal, msg: msg)?
                }
            }
        };
        self.state = state;

        Ok(r)
    }
}

impl Endpoints {
    fn boot_validate_info(this: Info, other: Info) -> Result<()> {
        if this.public_key != other.public_key {
            err_at!(Invalid, msg: format!("public-key mismatch"))
        } else if this.hash != other.hash {
            err_at!(Invalid, msg: format!("hash mismatch"))
        } else {
            Ok(())
        }
    }

    fn boot_validate_latest(this: Random, other: Random) -> Result<()> {
        if this.round != other.round {
            err_at!(Invalid, msg: format!("round mismatch"))
        } else if this.randomness != other.randomness {
            err_at!(Invalid, msg: format!("randomness mismatch"))
        } else if this.signature != other.signature {
            err_at!(Invalid, msg: format!("signature mismatch"))
        } else if this.previous_signature != other.previous_signature {
            err_at!(Invalid, msg: format!("previous_signature mismatch"))
        } else {
            Ok(())
        }
    }

    fn get_endpoint_pair(&self) -> (Option<Inner>, Option<Inner>) {
        use crate::http::MAX_ELAPSED;

        let mut endpoints = vec![];
        for (i, endp) in self.endpoints.iter().enumerate() {
            if endp.avg_elapsed() < MAX_ELAPSED {
                endpoints.push((i, endp.avg_elapsed()));
            }
        }
        endpoints.sort_by(|x, y| x.1.cmp(&y.1));

        let mut iter = endpoints.iter();
        match (iter.next(), iter.next()) {
            (Some((i, _)), Some((j, _))) => {
                let x = Some(self.endpoints[*i].clone());
                let y = Some(self.endpoints[*j].clone());
                (x, y)
            }
            (Some((i, _)), None) => {
                let x = Some(self.endpoints[*i].clone());
                let y = None;
                (x, y)
            }
            (None, _) => (None, None),
        }
    }
}

#[derive(Clone)]
enum Inner {
    Http(Http),
}

impl Inner {
    async fn boot_phase1(&mut self) -> Result<(Info, Random)> {
        match self {
            Inner::Http(endp) => endp.boot_phase1().await,
        }
    }

    async fn boot_phase2(&mut self, state: State, latest: Random) -> Result<State> {
        match self {
            Inner::Http(endp) => endp.boot_phase2(state, latest).await,
        }
    }

    async fn get(&mut self, state: State, round: Option<u128>) -> Result<(State, Random)> {
        match self {
            Inner::Http(endp) => endp.get(state, round).await,
        }
    }

    fn avg_elapsed(&self) -> time::Duration {
        match self {
            Inner::Http(endp) => endp.avg_elapsed(),
        }
    }
}

// State of each endpoint. An endpoint is booted and subsequently
// used to watch/get future rounds of random-ness.
#[derive(Clone)]
pub(crate) struct State {
    pub(crate) info: Info,
    pub(crate) check_point: Option<Random>,
    pub(crate) determinism: bool,
    pub(crate) secure: bool,
    pub(crate) rate_limit: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            info: Info::default(),
            check_point: None,
            determinism: bool::default(),
            secure: bool::default(),
            rate_limit: usize::default(),
        }
    }
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
        }
    }
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
