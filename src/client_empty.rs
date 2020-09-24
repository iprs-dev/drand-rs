#[derive(Clone)]
struct EmptyClient {
    public_key: (),
    period: time::Duration,
    genesis_time: time::SystemTime,
    hash: Vec<u8>,
}

impl From<EmptyClient> for ClientInfo {
    fn from(val: EmptyClient) -> Self {
        ClientInfo {
            public_key: val.public_key,
            period: val.period,
            genesis_time: val.genesis_time,
            hash: val.hash,
        }
    }
}

impl Client for EmptyClient {
    type I = EmptyClient;
    type R = ClientRound;

    fn new<I: Info>(info: I) -> EmptyClient {
        EmptyClient {
            public_key: info.to_public_key(),
            period: info.to_period(),
            genesis_time: info.to_genesis_time(),
            hash: info.to_info(),
        }
    }

    fn to_info(&self) -> Result<Info> {
        self.info.clone()
    }

    fn round_at(&self, t: time::SystemTime) -> Result<u128> {
        let next_round = match t.elapsed(self.info.genesis_time) {
            Ok(dur) => {
                let dur = dur.as_secs;
                // gives us the number of periods since genesis
                // we add +1 since we want the next round
                // we also add +1 because round 1 starts at genesis time.
                match dur % self.info.period {
                    0 => (dur / self.info.period) + 1,
                    _ => (dur / self.info.period) + 1 + 1,
                }
            }
            Err(_) => 1,
        };

        Ok(next_round)
    }

    fn get_round(&self, round: u128) -> Result<u128> {
        Err(Error::EmptyClient)
    }

    fn watch_rounds(&self) -> Result<Box<dyn Iterator<Item = Result<Self::R>>>> {
        Ok(Box::new(vec![].into_iter()))
    }
}

impl Info for EmptyClient {
    fn to_public_key(&self) -> () {
        self.public_key.clone()
    }

    fn to_period(&self) -> time::Duration {
        self.period.clone()
    }

    fn to_genesis_time(&self) -> time::SystemTime {
        self.genesis_time.clone()
    }

    fn as_hash(&self) -> &[u8] {
        self.hash.as_slice()
    }
}
