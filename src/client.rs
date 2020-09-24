use std::{result, fmt, time};

use crate::{Result, Error};

// TODO: prometheus interfacing.

struct Config {
    // insecure indicates whether root of trust is need.
    insecure: bool
    // from `chainInfo.Hash()` - serves as a root of trust for a given
    // randomness chain.
    chainHash []byte
    // Full chain information - serves as a root of trust.
    chainInfo *chain.Info
    // chain signature verification back to the 1st round, or to a know result to ensure
    // determinism in the event of a compromised chain.
    fullVerify bool

    // cache size - how large of a cache to keep locally.
    cacheSize int
    // clients is the set of options for fetching randomness
    clients: Vec<Client>
    // watcher is a constructor function for generating a new partial client of randomness
    watcher WatcherCtor
    // A previously fetched result serving as a verification checkpoint if one exists.
    previousResult Result
    // autoWatch causes the client to start watching immediately in the background so that new randomness
    // is proactively fetched and added to the cache.
    autoWatch bool
    // autoWatchRetry specifies the time after which the watch channel
    // created by the autoWatch is re-opened when no context error occurred.
    autoWatchRetry time.Duration
    // prometheus is an interface to a Prometheus system
    prometheus prometheus.Registerer
}

enum Client {
    Empty(Empty),
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Client::*;

        match self {
            Empty(info) => write!(f, "empty-client"),
        }
    }
}

impl Client {
    fn new_empty<I: Info>(info: I) -> Client {
        Client::Empty(Empty::new(info))
    }

    // makeClient creates a client from a configuration.
    fn makeClient(cfg *clientConfig) (Client, error) {
            if !cfg.insecure && cfg.chainHash == nil && cfg.chainInfo == nil {
                    return nil, errors.New("no root of trust specified")
            }
            if len(cfg.clients) == 0 && cfg.watcher == nil {
                    return nil, errors.New("no points of contact specified")
            }

            var err error

            // provision cache
            cache, err := makeCache(cfg.cacheSize)
            if err != nil {
                    return nil, err
            }

            // provision watcher client
            var wc Client
            if cfg.watcher != nil {
                    wc, err = makeWatcherClient(cfg, cache)
                    if err != nil {
                            return nil, err
                    }
                    cfg.clients = append(cfg.clients, wc)
            }

            for _, c := range cfg.clients {
                    trySetLog(c, cfg.log)
            }

            var c Client

            verifiers := make([]Client, 0, len(cfg.clients))
            for _, source := range cfg.clients {
                    nv := newVerifyingClient(source, cfg.previousResult, cfg.fullVerify)
                    verifiers = append(verifiers, nv)
                    if source == wc {
                            wc = nv
                    }
            }

            c, err = makeOptimizingClient(cfg, verifiers, wc, cache)
            if err != nil {
                    return nil, err
            }

            wa := newWatchAggregator(c, cfg.autoWatch, cfg.autoWatchRetry)
            c = wa
            trySetLog(c, cfg.log)

            wa.Start()

            return attachMetrics(cfg, c)
    }
}

impl DrandClient for Client {
    type I = ClientInfo;
    type R = ClientRound;

    fn to_info(&self) -> Result<Self::I> {
        use Client::*;

        match self {
            Empty(val) -> val.to_info().map(|info| into()),
        }
    }

    fn round_at(&self, t: time::SystemTime) -> Result<u128> {
        use Client::*;

        match self {
            Empty(val) -> val.to_round_at(t)
        }
    }

    fn get_round(&self, round: u128) -> Result<Self::R> {
        use Client::*;

        match self {
            Empty(val) -> val.get_round(round).map(|r| r.into())
        }
    }

    fn watch_rounds(&self) -> Result<Box<dyn Iterator<Item=Result<Self::R>>>> {
        use Client::*;

        let iter = match self {
            Empty(val) -> val.watch_rounds(t)?,
        };

        Ok(Box::new(iter.map(|item| item.map(|r| r.into()))))
    }
}

#[derive(Clone)]
struct ClientInfo {
    public_key: (),
    period: time::Duration,
    genesis_time: time::SystemTime,
    hash: Vec<u8>,
}

impl Info for ClientInfo {
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

#[derive(Default, Clone)]
struct ClientRound {
    round: u128,
    randomness: Vec<u8>,
    signature: Vec<u8>,
    previous_signature: Option<Vec<u8>>,
}

// Trait for a single drand round.
impl Round ClientRound {
    fn to_round(&self) -> u64 {
        self.round
    }

    fn as_randomness(&self) -> &[u8] {
        self.randomness.as_slice()
    }

    fn as_signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    fn as_pervious_signature(&self) -> Option<&[u8]> {
        self.previous_signature.as_ref()
    }
}
