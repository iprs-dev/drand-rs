use std::{future::Future, time};

use crate::{client::Endpoint, http::Http, Config, Error, Info, Random, Result};

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

impl From<Config> for State {
    fn from(mut cfg: Config) -> Self {
        State {
            info: Info::default(),
            check_point: cfg.check_point.take(),
            determinism: cfg.determinism,
            secure: cfg.secure,
            rate_limit: cfg.rate_limit,
        }
    }
}

// Endpoints is an enumeration of several known http endpoint from
// main-net.
pub struct Endpoints {
    state: State,
    endpoints: Vec<Inner>,
}

impl Endpoints {
    pub(crate) fn from_config(config: Config) -> Self {
        Endpoints {
            state: config.into(),
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

    pub(crate) fn boot<'a>(
        &'a mut self,
        chain_hash: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<()>> + 'a {
        async move {
            // root of trust.
            let rot = chain_hash.as_ref().map(|x| x.as_slice());

            let (info, latest) = match self.endpoints.len() {
                0 => err_at!(Invalid, msg: format!("initialize endpoint"))?,
                1 => self.endpoints[0].boot_phase1(rot).await?,
                _ => {
                    let (info, latest) = {
                        let endp = &mut self.endpoints[0];
                        endp.boot_phase1(rot).await?
                    };

                    let mut tail = vec![];
                    for mut endp in self.endpoints[1..].to_vec() {
                        let (info1, latest1) = (info.clone(), latest.clone());
                        tail.push(async {
                            let (info2, _) = endp.boot_phase1(rot).await?;

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
    }

    pub(crate) fn get<'a>(
        &'a mut self,
        round: Option<u128>,
    ) -> impl Future<Output = Result<Random>> + 'a {
        async move {
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

    pub(crate) fn to_info(&self) -> Info {
        self.state.info.clone()
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
    async fn boot_phase1(&mut self, rot: Option<&[u8]>) -> Result<(Info, Random)> {
        match self {
            Inner::Http(endp) => endp.boot_phase1(rot).await,
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
