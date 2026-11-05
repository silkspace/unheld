//! Queues on disk: a directory per queue, a file per blob, named by its number. Blobs are never
//! deleted one by one, so the numbers are dense and the count is the next number.

use crate::config::{self, files, limits};
use crate::wire::{Capability, Hash, QueueId, Request, Response};
use crate::{hex, RelayError};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use subtle::ConstantTimeEq as _;
use unheld_blob::Blob;

/// What one relay enforces (L13).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub depth: u64,
    pub puts_per_minute: usize,
    pub queues: usize,
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            depth: limits::DEPTH,
            puts_per_minute: limits::PUTS_PER_MINUTE,
            queues: limits::QUEUES,
            idle: Duration::from_secs(limits::IDLE_SECS),
        }
    }
}

#[derive(Default)]
struct State {
    recent: HashMap<QueueId, VecDeque<Instant>>,
    queues: usize,
}

/// The relay's whole state: a directory and the limits.
pub struct Relay {
    root: PathBuf,
    limits: Limits,
    state: Mutex<State>,
}

/// The hash a capability is stored as.
pub fn hash_of(cap: &Capability) -> Hash {
    Sha256::digest(cap).into()
}

fn seq_name(seq: u64) -> String {
    format!("{seq:0width$}", width = files::SEQ_DIGITS)
}

impl Relay {
    /// Open or create the store under `dir`.
    pub fn open(dir: &Path, limits: Limits) -> Result<Relay, RelayError> {
        let root = dir.join(files::QUEUES);
        std::fs::create_dir_all(&root)?;
        let queues = std::fs::read_dir(&root)?.filter_map(Result::ok).filter(|e| e.path().is_dir()).count();
        Ok(Relay { root, limits, state: Mutex::new(State { recent: HashMap::new(), queues }) })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn dir(&self, id: &QueueId) -> PathBuf {
        self.root.join(hex(id))
    }

    /// Whether `cap` opens the capability file `name` of queue `id`. A missing queue and a wrong
    /// capability take the same path and give the same answer.
    fn allows(&self, id: &QueueId, name: &str, cap: &Capability) -> bool {
        let stored: Hash = std::fs::read(self.dir(id).join(name))
            .ok()
            .and_then(|v| v.try_into().ok())
            .unwrap_or([0u8; config::HASH_LEN]);
        bool::from(hash_of(cap).ct_eq(&stored))
    }

    /// Blobs in the queue, which is also the number the next one gets minus one.
    fn depth(&self, id: &QueueId) -> Result<u64, RelayError> {
        let n = std::fs::read_dir(self.dir(id))?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().len() == files::SEQ_DIGITS)
            .count();
        Ok(n as u64)
    }

    fn too_fast(&self, id: &QueueId, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let recent = state.recent.entry(*id).or_default();
        while recent.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            recent.pop_front();
        }
        if recent.len() >= self.limits.puts_per_minute {
            return true;
        }
        recent.push_back(now);
        false
    }

    /// Answer one request. The lock is held for the whole call, so numbers are assigned in
    /// one order and that order is the one every reader sees.
    pub fn handle(&self, req: Request) -> Result<Response, RelayError> {
        match req {
            Request::Create { id, write, read } => {
                let dir = self.dir(&id);
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.queues >= self.limits.queues {
                    return Ok(Response::Full);
                }
                if std::fs::create_dir(&dir).is_err() {
                    return Ok(Response::Refused);
                }
                std::fs::write(dir.join(files::WRITE_HASH), write)?;
                std::fs::write(dir.join(files::READ_HASH), read)?;
                state.queues += 1;
                Ok(Response::Done)
            }
            Request::Put { id, write, blob } => {
                if !self.allows(&id, files::WRITE_HASH, &write) {
                    return Ok(Response::Refused);
                }
                let _order = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let depth = self.depth(&id)?;
                if depth >= self.limits.depth {
                    return Ok(Response::Full);
                }
                drop(_order);
                if self.too_fast(&id, Instant::now()) {
                    return Ok(Response::TooFast);
                }
                let seq = depth + 1;
                let path = self.dir(&id).join(seq_name(seq));
                let tmp = self.dir(&id).join(format!("{}.part", seq_name(seq)));
                std::fs::write(&tmp, blob.as_bytes())?;
                std::fs::rename(&tmp, &path)?;
                Ok(Response::Seq(seq))
            }
            Request::Get { id, read, after } => {
                if !self.allows(&id, files::READ_HASH, &read) {
                    return Ok(Response::Refused);
                }
                let seq = after.saturating_add(1);
                match std::fs::read(self.dir(&id).join(seq_name(seq))) {
                    Ok(bytes) => {
                        let blob = Blob::from_bytes(bytes).map_err(|_| RelayError::Malformed)?;
                        Ok(Response::Next(seq, blob))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Response::Nothing),
                    Err(e) => Err(e.into()),
                }
            }
            Request::Delete { id, read } => {
                if !self.allows(&id, files::READ_HASH, &read) {
                    return Ok(Response::Refused);
                }
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                std::fs::remove_dir_all(self.dir(&id))?;
                state.queues = state.queues.saturating_sub(1);
                state.recent.remove(&id);
                Ok(Response::Done)
            }
        }
    }

    /// Forget every queue whose last put is older than the idle limit. Returns how many.
    pub fn sweep(&self, now: SystemTime) -> Result<usize, RelayError> {
        let mut gone = 0;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for entry in std::fs::read_dir(&self.root)?.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let last = std::fs::read_dir(&path)?
                .filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok()?.modified().ok())
                .max()
                .unwrap_or(SystemTime::UNIX_EPOCH);
            if now.duration_since(last).unwrap_or_default() >= self.limits.idle {
                std::fs::remove_dir_all(&path)?;
                state.queues = state.queues.saturating_sub(1);
                gone += 1;
            }
        }
        Ok(gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-relay-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn queue(relay: &Relay) -> (QueueId, Capability, Capability) {
        let (id, w, r) = ([7u8; 32], [8u8; 32], [9u8; 32]);
        assert_eq!(relay.handle(Request::Create { id, write: hash_of(&w), read: hash_of(&r) }).unwrap(), Response::Done);
        (id, w, r)
    }

    #[test]
    fn numbers_are_dense_and_the_order_is_the_relays() {
        let relay = Relay::open(&tmp("order"), Limits::default()).unwrap();
        let (id, w, r) = queue(&relay);
        let blobs: Vec<Blob> = (0..3u8).map(|i| Blob::pad(&[i]).unwrap()).collect();
        for (i, b) in blobs.iter().enumerate() {
            assert_eq!(relay.handle(Request::Put { id, write: w, blob: b.clone() }).unwrap(), Response::Seq(i as u64 + 1));
        }
        let mut after = 0;
        for b in &blobs {
            match relay.handle(Request::Get { id, read: r, after }).unwrap() {
                Response::Next(n, got) => {
                    assert_eq!(n, after + 1);
                    assert_eq!(&got, b);
                    after = n;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(relay.handle(Request::Get { id, read: r, after }).unwrap(), Response::Nothing);
        // A second reader sees the same numbers.
        assert!(matches!(relay.handle(Request::Get { id, read: r, after: 0 }).unwrap(), Response::Next(1, _)));
    }

    #[test]
    fn a_wrong_capability_an_unknown_queue_and_a_taken_id_are_one_refusal() {
        let relay = Relay::open(&tmp("caps"), Limits::default()).unwrap();
        let (id, w, r) = queue(&relay);
        let blob = Blob::pad(b"x").unwrap();
        assert_eq!(relay.handle(Request::Put { id, write: r, blob: blob.clone() }).unwrap(), Response::Refused);
        assert_eq!(relay.handle(Request::Get { id, read: w, after: 0 }).unwrap(), Response::Refused);
        assert_eq!(relay.handle(Request::Put { id: [0; 32], write: w, blob }).unwrap(), Response::Refused);
        assert_eq!(relay.handle(Request::Delete { id, read: w }).unwrap(), Response::Refused);
        assert_eq!(relay.handle(Request::Create { id, write: [1; 32], read: [2; 32] }).unwrap(), Response::Refused);
        // The original capabilities still work after the failed takeover.
        assert_eq!(relay.handle(Request::Delete { id, read: r }).unwrap(), Response::Done);
        assert_eq!(relay.handle(Request::Get { id, read: r, after: 0 }).unwrap(), Response::Refused);
    }

    #[test]
    fn depth_and_rate_are_bounds_not_crashes() {
        let limits = Limits { depth: 3, puts_per_minute: 2, queues: 1, ..Limits::default() };
        let relay = Relay::open(&tmp("bounds"), limits).unwrap();
        let (id, w, _) = queue(&relay);
        let blob = Blob::pad(b"x").unwrap();
        assert_eq!(relay.handle(Request::Put { id, write: w, blob: blob.clone() }).unwrap(), Response::Seq(1));
        assert_eq!(relay.handle(Request::Put { id, write: w, blob: blob.clone() }).unwrap(), Response::Seq(2));
        assert_eq!(relay.handle(Request::Put { id, write: w, blob: blob.clone() }).unwrap(), Response::TooFast);
        // Depth is checked before rate, so a full queue says full.
        let relay2 = Relay::open(&tmp("bounds2"), Limits { puts_per_minute: 100, ..limits }).unwrap();
        let (id2, w2, _) = queue(&relay2);
        for _ in 0..3 {
            assert!(matches!(relay2.handle(Request::Put { id: id2, write: w2, blob: blob.clone() }).unwrap(), Response::Seq(_)));
        }
        assert_eq!(relay2.handle(Request::Put { id: id2, write: w2, blob: blob.clone() }).unwrap(), Response::Full);
        assert_eq!(relay2.handle(Request::Create { id: [1; 32], write: [1; 32], read: [1; 32] }).unwrap(), Response::Full);
    }

    #[test]
    fn a_restarted_relay_delivers_what_it_had_and_forgets_the_idle() {
        let dir = tmp("restart");
        let (id, w, r) = {
            let relay = Relay::open(&dir, Limits::default()).unwrap();
            let q = queue(&relay);
            relay.handle(Request::Put { id: q.0, write: q.1, blob: Blob::pad(b"kept").unwrap() }).unwrap();
            q
        };
        let relay = Relay::open(&dir, Limits { idle: Duration::from_secs(3600), ..Limits::default() }).unwrap();
        assert!(matches!(relay.handle(Request::Get { id, read: r, after: 0 }).unwrap(), Response::Next(1, _)));
        assert_eq!(relay.handle(Request::Put { id, write: w, blob: Blob::pad(b"more").unwrap() }).unwrap(), Response::Seq(2));
        assert_eq!(relay.sweep(SystemTime::now()).unwrap(), 0);
        assert_eq!(relay.sweep(SystemTime::now() + Duration::from_secs(7200)).unwrap(), 1);
        assert_eq!(relay.handle(Request::Get { id, read: r, after: 0 }).unwrap(), Response::Refused);
    }
}
