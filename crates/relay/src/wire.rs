//! The three verbs and their answers as bytes. A frame is a big-endian length and a body; a body
//! is a tag and fixed-width fields, with the blob, when there is one, last.

use crate::config::{self, HASH_LEN, ID_LEN};
use crate::RelayError;
use std::io::{Read, Write};
use unheld_blob::Blob;

pub type QueueId = [u8; ID_LEN];
pub type Capability = [u8; ID_LEN];
pub type Hash = [u8; HASH_LEN];

/// What a client asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Create { id: QueueId, write: Hash, read: Hash },
    Put { id: QueueId, write: Capability, blob: Blob },
    Get { id: QueueId, read: Capability, after: u64 },
    Delete { id: QueueId, read: Capability },
}

/// What the relay answers. Nothing here is an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The queue was created or deleted.
    Done,
    /// The blob was appended and this is its number.
    Seq(u64),
    /// The next blob and its number.
    Next(u64, Blob),
    /// No blob after the number given.
    Nothing,
    /// Unknown queue, wrong capability, or a queue that already exists: one answer for all three.
    Refused,
    /// The queue holds its maximum (L13).
    Full,
    /// The queue took its maximum this minute (L13).
    TooFast,
    /// The request could not be read.
    Bad,
}

mod tag {
    pub const CREATE: u8 = 1;
    pub const PUT: u8 = 2;
    pub const GET: u8 = 3;
    pub const DELETE: u8 = 4;
    pub const DONE: u8 = 0;
    pub const SEQ: u8 = 1;
    pub const NEXT: u8 = 2;
    pub const NOTHING: u8 = 3;
    pub const REFUSED: u8 = 16;
    pub const FULL: u8 = 17;
    pub const TOO_FAST: u8 = 18;
    pub const BAD: u8 = 19;
}

fn take<const N: usize>(body: &[u8], at: usize) -> Result<[u8; N], RelayError> {
    body.get(at..at + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(RelayError::Malformed)
}

fn take_u64(body: &[u8], at: usize) -> Result<u64, RelayError> {
    take::<8>(body, at).map(u64::from_be_bytes)
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Request::Create { id, write, read } => {
                v.push(tag::CREATE);
                v.extend_from_slice(id);
                v.extend_from_slice(write);
                v.extend_from_slice(read);
            }
            Request::Put { id, write, blob } => {
                v.push(tag::PUT);
                v.extend_from_slice(id);
                v.extend_from_slice(write);
                v.extend_from_slice(blob.as_bytes());
            }
            Request::Get { id, read, after } => {
                v.push(tag::GET);
                v.extend_from_slice(id);
                v.extend_from_slice(read);
                v.extend_from_slice(&after.to_be_bytes());
            }
            Request::Delete { id, read } => {
                v.push(tag::DELETE);
                v.extend_from_slice(id);
                v.extend_from_slice(read);
            }
        }
        v
    }

    /// Read a request from a body. Anything but an exact encoding is malformed.
    pub fn decode(body: &[u8]) -> Result<Request, RelayError> {
        let tag = *body.first().ok_or(RelayError::Malformed)?;
        let id = take::<ID_LEN>(body, 1)?;
        let second = take::<ID_LEN>(body, 1 + ID_LEN)?;
        let rest = &body[1 + 2 * ID_LEN..];
        match tag {
            tag::CREATE => {
                let read = take::<HASH_LEN>(body, 1 + 2 * ID_LEN)?;
                if rest.len() != HASH_LEN {
                    return Err(RelayError::Malformed);
                }
                Ok(Request::Create { id, write: second, read })
            }
            tag::PUT => {
                let blob = Blob::from_bytes(rest.to_vec()).map_err(|_| RelayError::Malformed)?;
                Ok(Request::Put { id, write: second, blob })
            }
            tag::GET => {
                if rest.len() != 8 {
                    return Err(RelayError::Malformed);
                }
                Ok(Request::Get { id, read: second, after: take_u64(body, 1 + 2 * ID_LEN)? })
            }
            tag::DELETE => {
                if !rest.is_empty() {
                    return Err(RelayError::Malformed);
                }
                Ok(Request::Delete { id, read: second })
            }
            _ => Err(RelayError::Malformed),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Response::Done => v.push(tag::DONE),
            Response::Seq(n) => {
                v.push(tag::SEQ);
                v.extend_from_slice(&n.to_be_bytes());
            }
            Response::Next(n, blob) => {
                v.push(tag::NEXT);
                v.extend_from_slice(&n.to_be_bytes());
                v.extend_from_slice(blob.as_bytes());
            }
            Response::Nothing => v.push(tag::NOTHING),
            Response::Refused => v.push(tag::REFUSED),
            Response::Full => v.push(tag::FULL),
            Response::TooFast => v.push(tag::TOO_FAST),
            Response::Bad => v.push(tag::BAD),
        }
        v
    }

    pub fn decode(body: &[u8]) -> Result<Response, RelayError> {
        let tag = *body.first().ok_or(RelayError::Malformed)?;
        let rest = &body[1..];
        let bare = |r: Response| if rest.is_empty() { Ok(r) } else { Err(RelayError::Malformed) };
        match tag {
            tag::DONE => bare(Response::Done),
            tag::NOTHING => bare(Response::Nothing),
            tag::REFUSED => bare(Response::Refused),
            tag::FULL => bare(Response::Full),
            tag::TOO_FAST => bare(Response::TooFast),
            tag::BAD => bare(Response::Bad),
            tag::SEQ => {
                if rest.len() != 8 {
                    return Err(RelayError::Malformed);
                }
                Ok(Response::Seq(take_u64(body, 1)?))
            }
            tag::NEXT => {
                let n = take_u64(body, 1)?;
                let blob = Blob::from_bytes(body[9..].to_vec()).map_err(|_| RelayError::Malformed)?;
                Ok(Response::Next(n, blob))
            }
            _ => Err(RelayError::Malformed),
        }
    }
}

/// Write one frame: the body's length, then the body.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> Result<(), RelayError> {
    if body.len() > config::MAX_BODY {
        return Err(RelayError::Malformed);
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame. A length above the largest body is refused before any of it is read.
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, RelayError> {
    let mut prefix = [0u8; config::FRAME_PREFIX];
    r.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > config::MAX_BODY {
        return Err(RelayError::Malformed);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_and_response_round_trips() {
        let blob = Blob::pad(b"x").unwrap();
        let reqs = [
            Request::Create { id: [1; 32], write: [2; 32], read: [3; 32] },
            Request::Put { id: [1; 32], write: [2; 32], blob: blob.clone() },
            Request::Get { id: [1; 32], read: [3; 32], after: 7 },
            Request::Delete { id: [1; 32], read: [3; 32] },
        ];
        for r in reqs {
            assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        }
        let resps = [
            Response::Done,
            Response::Seq(9),
            Response::Next(10, blob),
            Response::Nothing,
            Response::Refused,
            Response::Full,
            Response::TooFast,
            Response::Bad,
        ];
        for r in resps {
            assert_eq!(Response::decode(&r.encode()).unwrap(), r);
        }
    }

    #[test]
    fn a_short_or_padded_body_is_malformed() {
        let good = Request::Get { id: [1; 32], read: [3; 32], after: 7 }.encode();
        assert!(Request::decode(&good[..good.len() - 1]).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(Request::decode(&long).is_err());
        assert!(Request::decode(&[]).is_err());
        assert!(Request::decode(&[9; 73]).is_err());
        // A put whose blob is not a bucket is malformed, so the relay never stores one.
        let mut put = Request::Put { id: [1; 32], write: [2; 32], blob: Blob::pad(b"x").unwrap() }.encode();
        put.pop();
        assert!(Request::decode(&put).is_err());
    }

    #[test]
    fn a_frame_above_the_largest_body_is_refused_before_it_is_read() {
        let mut too_long = ((config::MAX_BODY + 1) as u32).to_be_bytes().to_vec();
        too_long.extend_from_slice(&[0; 8]);
        assert!(matches!(read_frame(&mut &too_long[..]), Err(RelayError::Malformed)));
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &vec![0; config::MAX_BODY + 1]).is_err());
        write_frame(&mut out, b"abc").unwrap();
        assert_eq!(read_frame(&mut &out[..]).unwrap(), b"abc");
    }
}
