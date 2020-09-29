use std::time;

#[macro_use]
mod util;
mod client;
mod core;
mod endpoints;
mod http;
mod verify;

pub use crate::client::Client;
pub use crate::core::{Config, Error, Info, Random, Result};

const MAINNET_CHAIN_HASH: &'static str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";

// Trait for DrandClient, must eventually move to Client type.
trait DrandClient {
    /// Returns parameters of the chain this client is connected to.
    /// The public key, when it started, and how frequently it updates.
    fn to_info(&self) -> Result<Info>;

    /// Return the most recent round of randomness that will be available
    /// at time for the current client.
    fn round_at(&self, t: time::SystemTime) -> u128;

    /// Returns a the randomness at `round` or an error.
    /// Requesting round = 0 will return randomness for the most
    /// recent known round.
    fn get(&self, round: u128) -> Result<Random>;

    /// Returns new randomness as it becomes available.
    fn watch(&self) -> Result<Box<dyn Iterator<Item = Result<Random>>>>;
}
