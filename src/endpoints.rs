use crate::{
    http::{Info, Random},
    Config, Result, Round,
};

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
            info: Info::default(),
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
pub(crate) struct State {
    pub(crate) info: Info,
    pub(crate) check_point: Option<Random>,
    pub(crate) determinism: bool,
    pub(crate) secure: bool,
    pub(crate) rate_limit: usize,
}
