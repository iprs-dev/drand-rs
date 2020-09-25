use std::{error, fmt, result, time};

#[macro_use]
mod util;
mod endpoints;
mod http;

pub const MAINNET_CHAIN_HASH: &'static str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";

// Trait for DrandClient, must eventually move to Client type.
trait DrandClient {
    type I: Info;
    type R: Round;

    /// Returns parameters of the chain this client is connected to.
    /// The public key, when it started, and how frequently it updates.
    fn to_info(&self) -> Result<Self::I>;

    /// Return the most recent round of randomness that will be available
    /// at time for the current client.
    fn round_at(&self, t: time::SystemTime) -> u128;

    /// Returns a the randomness at `round` or an error.
    /// Requesting round = 0 will return randomness for the most
    /// recent known round.
    fn get(&self, round: u128) -> Result<Self::R>;

    /// Returns new randomness as it becomes available.
    fn watch(&self) -> Result<Box<dyn Iterator<Item = Result<Self::R>>>>;
}

// Trait for an endpoint info.
pub trait Info {
    /// Return public key
    fn as_public_key(&self) -> &[u8];

    /// Return randomness period in seconds
    fn to_period(&self) -> time::Duration;

    /// Return genesis-time for this endpoint
    fn to_genesis_time(&self) -> time::SystemTime;

    /// Return root hash
    fn as_hash(&self) -> &[u8];
}

// Trait for a single drand round.
pub trait Round {
    /// Return round-number.
    fn to_round(&self) -> u128;

    /// Return a reference to randomness for this round
    fn as_randomness(&self) -> &[u8];

    /// Return a reference to signature for this round
    fn as_signature(&self) -> &[u8];

    /// Return a reference to signature for the previous round
    fn as_previous_signature(&self) -> Option<&[u8]>;

    /// Return the Sha256 digest of round-number and previous_signature
    fn to_digest(&self) -> Result<Vec<u8>>;
}

pub struct Config<R: Round> {
    /// A previously fetched round serving as a verification checkpoint.
    ///
    /// * if `determinism` is true and check_point is None, Round-1 acts
    ///   as the the check_point round.
    /// * if `determinism` is false, lastest round is assumed as verified
    ///   round and treated as `check_point`.
    /// * if `secure` is false, every beacon round is assumed as verfied
    ///   round.
    /// * if `secure` is true, every new round is verified with
    ///   `check_point` round.
    pub check_point: Option<R>,
    /// Ensure all rounds from check_point to the latest round is valid
    pub determinism: bool,
    /// Ensure all future rounds from latest round is verified.
    pub secure: bool,
    /// Rate limit number of request client can make per minute.
    pub rate_limit: usize,
}

/// Type alias for Result return type, used by this package.
pub type Result<T> = result::Result<T, Error>;

/// Error variants that can be returned by this package's API.
///
/// Each variant carries a prefix, typically identifying the
/// error location.
pub enum Error {
    Fatal(String, String),
    Invalid(String, String),
    IOError(String, String),
    Parse(String, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Error::*;

        match self {
            Fatal(p, msg) => write!(f, "{} Fatal: {}", p, msg),
            Invalid(p, msg) => write!(f, "{} Invalid: {}", p, msg),
            IOError(p, msg) => write!(f, "{} IOError: {}", p, msg),
            Parse(p, msg) => write!(f, "{} Parse: {}", p, msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl error::Error for Error {}
