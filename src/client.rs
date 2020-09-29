//! Module implement client interface to drand-group.

use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use crate::{endpoints::Endpoints, Config, Error, Info, Random, Result};

/// List of available endpoints.
#[derive(Clone)]
pub enum Endpoint {
    /// https://api.drand.sh
    HttpDrandApi,
    /// https://api2.drand.sh
    HttpDrandApi2,
    /// https://api3.drand.sh
    HttpDrandApi3,
    /// https://drand.cloudflare.com
    HttpCloudflare,
}

/// Type to interface with league-of-entropy.
pub struct Client {
    name: String,
    inner: Arc<Mutex<RefCell<InnerClient>>>,
}

struct InnerClient {
    _config: Config,
    endpoints: Option<Endpoints>,
}

impl Client {
    /// Create a new client from `config` value, all clients are named.
    /// Caller can choose a meaningful name.
    pub fn from_config(name: &str, config: Config) -> Client {
        let inner = InnerClient {
            _config: config.clone(),
            endpoints: Some(Endpoints::from_config(name, config)),
        };
        Client {
            name: name.to_string(),
            inner: Arc::new(Mutex::new(RefCell::new(inner))),
        }
    }

    /// Add an endpoint to the client. Typically, endpoints are added to
    /// the [Client] instance before called after its [boot] method.
    pub fn add_endpoint(&mut self, endp: Endpoint) -> Result<&mut Self> {
        {
            let inner = err_at!(PoisonedLock, self.inner.lock())?;
            inner
                .borrow_mut()
                .endpoints
                .as_mut()
                .unwrap()
                .add_endpoint(endp);
        }
        Ok(self)
    }

    /// Return the hash-info from drand-group. This call is meaningful
    /// only after the [boot] method is called on this client.
    pub fn to_info(&self) -> Result<Info> {
        let info = {
            let inner = err_at!(PoisonedLock, self.inner.lock())?;
            let info = inner.borrow().endpoints.as_ref().unwrap().to_info();
            info
        };
        Ok(info)
    }

    /// Return back the client's name.
    pub fn to_name(&self) -> String {
        self.name.clone()
    }

    /// Boot a client. Will verify the endpoint's hash-info and if
    /// configured verify the chain of randomness from root-of-trust or
    /// previous-check-point to latest randomness.
    pub fn boot(&mut self, chain_hash: Option<Vec<u8>>) -> Result<()> {
        use futures::executor::block_on;

        let fut = async {
            let inner = err_at!(PoisonedLock, self.inner.lock())?;
            inner
                .borrow_mut()
                .endpoints
                .as_mut()
                .unwrap()
                .boot(chain_hash)
                .await?;
            Ok::<(), Error>(())
        };
        block_on(fut)
    }

    /// Get requested round of randomness.
    pub fn get(&mut self, round: Option<u128>) -> Result<Random> {
        use futures::executor::block_on;

        let fut = async {
            let inner = err_at!(PoisonedLock, self.inner.lock())?;
            let r = inner
                .borrow_mut()
                .endpoints
                .as_mut()
                .unwrap()
                .get(round)
                .await?;
            Ok::<Random, Error>(r)
        };
        block_on(fut)
    }
}

#[cfg(test)]
#[path = "client_test.rs"]
mod client_test;
