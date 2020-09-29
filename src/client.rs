use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use crate::{endpoints::Endpoints, Config, Error, Info, Random, Result};

#[derive(Clone)]
pub enum Endpoint {
    HttpDrandApi,
    HttpDrandApi2,
    HttpDrandApi3,
    HttpCloudflare,
}

pub struct Client {
    name: String,
    inner: Arc<Mutex<RefCell<InnerClient>>>,
}

struct InnerClient {
    _config: Config,
    endpoints: Option<Endpoints>,
}

impl Client {
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

    pub fn to_info(&self) -> Result<Info> {
        let info = {
            let inner = err_at!(PoisonedLock, self.inner.lock())?;
            let info = inner.borrow().endpoints.as_ref().unwrap().to_info();
            info
        };
        Ok(info)
    }

    pub fn to_name(&self) -> String {
        self.name.clone()
    }

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

//impl DrandClient for Client {
//    type I = ClientInfo;
//    type R = ClientRound;
//
//    fn to_info(&self) -> Result<Self::I> {
//        use Client::*;
//
//        match self {
//            Empty(val) -> val.to_info().map(|info| into()),
//        }
//    }
//
//    fn round_at(&self, t: time::SystemTime) -> Result<u128> {
//        use Client::*;
//
//        match self {
//            Empty(val) -> val.to_round_at(t)
//        }
//    }
//
//    fn get_round(&self, round: u128) -> Result<Self::R> {
//        use Client::*;
//
//        match self {
//            Empty(val) -> val.get_round(round).map(|r| r.into())
//        }
//    }
//
//    fn watch_rounds(&self) -> Result<Box<dyn Iterator<Item=Result<Self::R>>>> {
//        use Client::*;
//
//        let iter = match self {
//            Empty(val) -> val.watch_rounds(t)?,
//        };
//
//        Ok(Box::new(iter.map(|item| item.map(|r| r.into()))))
//    }
//}

#[cfg(test)]
#[path = "client_test.rs"]
mod client_test;
