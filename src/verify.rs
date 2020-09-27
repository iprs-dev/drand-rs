// TODO: use github version of drand-verify, not the local version.

use crate::{
    endpoints::{Endpoints, State},
    Error, Info, Random, Result,
};

#[derive(Clone)]
struct Remote {
    endp: Endpoint,
    elapsed: time::Duration,
}

pub(crate) fn boot_verify<R>(from: u128, till: u128, step: usize) -> impl Iterator<Item = R>
where
    R: Iterator<Item = u128>,
{
    let mut iter = Iter {
        start: from,
        till: from.saturating_sub(1),
        end: till,
        step,
    };
}

async fn swarm_swarm_verify<R>(
    pk: &[u8],
    remotes: Vec<Remote>,
    client: &reqwest::Client,
    swarm_swarm: impl Iterator<Item = R>,
    mut prev: Random,
) where R: Iterator<Item = u128> {
    let mut rmotes = remotes.clone();
    let mut swarms: Vec<R> = swarm_swarm.take(rmotes.len()).collect();
    prev = while swarms.len() > 0 {
        for (swarm, remote) in swarms.drain(..).zip(rmotes.drain(..)) {
            match swarm_verify(pk, remote, client, swarm) {
                Ok((first, last, remote)) => rmotes.push(remote);
                Err(Error::IOError(_, _)) => swarms.push(swarm);
                res => res?
            }
        }
    };
}

async fn swarm_verify(
    pk: &[u8]
    mut remote: Remote,
    client: &reqwest::Client,
    swarm: impl Iterator<Item = u128>,
) -> Result<(Random, Random, Remote)> {

    let rounds = vec![];
    for round in swarm {
        let url = {
            let ep = remote.endp.to_base_url();
            ep + "/public/" + &round.to_string()
        };
        rounds.push(async {
            let start = time::Instant::now();
            let resp = err_at!(IOError, client.get(url.as_str()).send().await)?;
            let r: Random = {
                let r: RandomJson = err_at!(IOError, resp.json().await)?;
                r.try_into()?
            };
            Ok::<(Random, time::Duration), Error>((r, start.elapsed()))
        });
    }

    let (mut randoms, mut elapsed) = (vec![], time::Duration::default());
    for item in futures::future::join_all(rounds).await {
        let (random, t) = item?;
        randoms.push(random);
        elapsed += t;
    }
    remote.elapsed = elapsed / (randoms.len() as u32);

    let first = randoms.remove(0);
    let (mut prev, mut last) = (first.clone(), first.clone());
    for r in randoms.into_iter() {
        if !verify_chain(pk, &prev.signature, &r)? {
            err_at!(NotSecure, msg: format!("fail verify {}", r))?;
        }
        prev = r.clone();
        last = r;
    }

    Ok((first, last, remote))
}

struct Iter {
    start: u128, // inclusive
    till: u128,  // previous item inclusive
    end: u128,   // inclusive
    step: usize,
}

impl Iterator for Iter {
    type Item = std::ops::RangeInclusive<u128>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.till.saturating_add(1) {
            from if from > self.end => None,
            from => {
                self.till = cmp::min(from + self.step, self.end);
                Some(from..=self.till)
            }
        }
    }
}

fn verify_chain(pk: &[u8], previous_signature: &[u8], curr: &Random) -> Result<bool> {
    if previous_signature != curr.previous_signature.as_slice() {
        let s = hex::encode(previous_signature);
        let p = hex::encode(&curr.previous_signature);
        // TODO: display as hex.
        err_at!(NotSecure, msg: format!("mismatch chain {:?} != {:?}", s, p))?
    }

    let pk = {
        let mut bytes: [u8; 48] = [0_u8; 48];
        bytes[..].clone_from_slice(&pk);
        err_at!(NotSecure, drand_verify::g1_from_fixed(bytes))?
    };

    Ok(err_at!(
        NotSecure,
        drand_verify::verify(&pk, curr.round as u64, &previous_signature, &curr.signature)
    )?)
}

#[cfg(test)]
#[path = "verify_test.rs"]
mod verify_test;
