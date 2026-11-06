//! The client side: a `Carrier` over a link, which is a queue to send on and a queue to receive
//! from, held with their capabilities and the read cursor in a file of its own, never in the
//! vault (docs/decisions/008-queue-per-direction.md). Between two people the two queues are
//! different and each is on the relay its reader chose; for a group they are one queue, and a
//! holder skips the numbers it wrote itself. A number out of sequence is an error before the core
//! sees the blob (L12). `LocalTransport` runs a relay in process, with an adversary at the
//! switches, so the carrier is tested against a relay that drops, swaps and replays.

use crate::config::{self, ID_LEN};
use crate::store::{hash_of, Relay};
use crate::tls::{client_config, Pin};
use crate::wire::{read_frame, write_frame, Capability, QueueId, Request, Response};
use crate::{hex, random, unhex, RelayError};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use unheld_blob::{Blob, Carrier, CarrierError};

/// One request, one answer, to the relay an endpoint names.
pub trait Transport {
    fn call(&mut self, at: &Endpoint, request: &Request) -> Result<Response, RelayError>;
}

/// Where a queue is and which one: the relay, the pin that authenticates it, and the identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub relay: String,
    pub pin: Pin,
    pub id: QueueId,
}

/// One direction of a conversation: a queue and the one capability this holder has for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Half {
    pub at: Endpoint,
    pub capability: Capability,
}

/// A conversation's queues as one person holds them. `send` is appended to and `receive` is
/// collected from; they are two queues between two people and one queue for a group. `after` is
/// the last number collected, and `mine` the numbers this holder wrote into a queue it also
/// reads and has not yet passed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub send: Option<Half>,
    pub receive: Option<Half>,
    pub after: u64,
    pub mine: BTreeSet<u64>,
}

/// The file form. Every field is lower-case hex but the relay's `host:port` and the numbers.
#[derive(Serialize, Deserialize)]
struct HalfFile {
    relay: String,
    pin: String,
    queue: String,
    capability: String,
}

#[derive(Serialize, Deserialize)]
struct LinkFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    send: Option<HalfFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receive: Option<HalfFile>,
    #[serde(default)]
    after: u64,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    mine: BTreeSet<u64>,
}

/// A relay address with no queue, `unheld-relay://host:port#<pin>`, as `unheld-relay init` prints it.
pub fn parse_relay(address: &str) -> Result<(String, Pin), RelayError> {
    let rest = address.strip_prefix(config::SCHEME).ok_or(RelayError::BadAddress)?;
    let (relay, pin) = rest.split_once('#').ok_or(RelayError::BadAddress)?;
    if relay.is_empty() || relay.contains('/') {
        return Err(RelayError::BadAddress);
    }
    Ok((relay.to_string(), Pin::parse(pin)?))
}

impl Half {
    /// `unheld-relay://host:port/<queue>/<capability>#<pin>`: where, which, and the right to
    /// one verb on it. The write half of a fresh queue in this form is the invitation its reader
    /// hands to the one person who will send on it.
    pub fn to_text(&self) -> String {
        format!("{}{}/{}/{}#{}", config::SCHEME, self.at.relay, hex(&self.at.id), hex(&self.capability), self.at.pin.to_hex())
    }

    pub fn parse(text: &str) -> Result<Half, RelayError> {
        let rest = text.trim().strip_prefix(config::SCHEME).ok_or(RelayError::BadAddress)?;
        let (path, pin) = rest.split_once('#').ok_or(RelayError::BadAddress)?;
        let mut parts = path.split('/');
        let relay = parts.next().filter(|r| !r.is_empty()).ok_or(RelayError::BadAddress)?;
        let id = parts.next().and_then(unhex::<ID_LEN>).ok_or(RelayError::BadAddress)?;
        let capability = parts.next().and_then(unhex::<ID_LEN>).ok_or(RelayError::BadAddress)?;
        if parts.next().is_some() {
            return Err(RelayError::BadAddress);
        }
        Ok(Half { at: Endpoint { relay: relay.to_string(), pin: Pin::parse(pin)?, id }, capability })
    }

    fn to_file(&self) -> HalfFile {
        HalfFile { relay: self.at.relay.clone(), pin: self.at.pin.to_hex(), queue: hex(&self.at.id), capability: hex(&self.capability) }
    }

    fn from_file(file: HalfFile) -> Result<Half, RelayError> {
        Ok(Half {
            at: Endpoint {
                relay: file.relay,
                pin: Pin::parse(&file.pin)?,
                id: unhex::<ID_LEN>(&file.queue).ok_or(RelayError::BadAddress)?,
            },
            capability: unhex::<ID_LEN>(&file.capability).ok_or(RelayError::BadAddress)?,
        })
    }
}

impl Link {
    pub fn load(path: &Path) -> Result<Link, RelayError> {
        let file: LinkFile = serde_json::from_slice(&std::fs::read(path)?).map_err(|_| RelayError::BadAddress)?;
        Ok(Link {
            send: file.send.map(Half::from_file).transpose()?,
            receive: file.receive.map(Half::from_file).transpose()?,
            after: file.after,
            mine: file.mine,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), RelayError> {
        let file = LinkFile {
            send: self.send.as_ref().map(Half::to_file),
            receive: self.receive.as_ref().map(Half::to_file),
            after: self.after,
            mine: self.mine.clone(),
        };
        let text = serde_json::to_string_pretty(&file).map_err(|_| RelayError::BadAddress)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Whether what this holder sends comes back to it: one queue for both directions.
    pub fn shared(&self) -> bool {
        matches!((&self.send, &self.receive), (Some(s), Some(r)) if s.at == r.at)
    }

    /// The write half of this holder's own queue, while it is still held: what one other person
    /// is given so that they can send here. `None` once `join` has pointed `send` elsewhere.
    pub fn invitation(&self) -> Option<String> {
        self.shared().then(|| self.send.as_ref().map(Half::to_text)).flatten()
    }

    /// Point `send` at another person's queue, with the write half they handed over.
    pub fn join(&mut self, invitation: &str) -> Result<(), RelayError> {
        self.send = Some(Half::parse(invitation)?);
        Ok(())
    }

    /// Move the cursor over every number this holder wrote that is next in line.
    fn skip_mine(&mut self) {
        while self.mine.remove(&(self.after + 1)) {
            self.after += 1;
        }
    }

    fn wrote(&mut self, seq: u64) {
        if self.shared() && seq > self.after {
            self.mine.insert(seq);
            self.skip_mine();
        }
    }
}

/// Connections to relays, one per relay, each trusting one pin and reopened when it breaks.
#[derive(Default)]
pub struct TlsTransport {
    configs: HashMap<Pin, Arc<ClientConfig>>,
    streams: HashMap<String, StreamOwned<ClientConnection, TcpStream>>,
}

impl TlsTransport {
    pub fn new() -> TlsTransport {
        TlsTransport::default()
    }

    fn connect(&mut self, at: &Endpoint) -> Result<&mut StreamOwned<ClientConnection, TcpStream>, RelayError> {
        if !self.streams.contains_key(&at.relay) {
            let config = match self.configs.get(&at.pin) {
                Some(c) => Arc::clone(c),
                None => {
                    let c = client_config(at.pin)?;
                    self.configs.insert(at.pin, Arc::clone(&c));
                    c
                }
            };
            let host = at.relay.rsplit_once(':').map(|(h, _)| h).unwrap_or(&at.relay);
            let name = ServerName::try_from(host.to_string()).map_err(|_| RelayError::BadAddress)?;
            let tcp = TcpStream::connect(&at.relay)?;
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(config::limits::SILENCE_SECS)))?;
            let conn = ClientConnection::new(config, name)?;
            self.streams.insert(at.relay.clone(), StreamOwned::new(conn, tcp));
        }
        Ok(self.streams.get_mut(&at.relay).expect("just set"))
    }
}

impl Transport for TlsTransport {
    fn call(&mut self, at: &Endpoint, request: &Request) -> Result<Response, RelayError> {
        let result = (|| {
            let stream = self.connect(at)?;
            write_frame(stream, &request.encode())?;
            Response::decode(&read_frame(stream)?)
        })();
        if result.is_err() {
            self.streams.remove(&at.relay);
        }
        result
    }
}

/// What a hostile relay does at the switches, by position in the queue as the reader asks for it.
#[derive(Clone, Debug, Default)]
pub struct Adversary {
    /// Positions never delivered: the reader asking for one gets the next instead.
    pub drop: Vec<u64>,
    /// Pairs of positions whose contents are exchanged, with the numbers kept.
    pub swap: Vec<(u64, u64)>,
    /// Positions whose content is served again at the position after.
    pub replay: Vec<u64>,
}

/// A relay in this process, reached directly whatever the endpoint says, with an adversary in the way.
pub struct LocalTransport {
    relay: Arc<Relay>,
    pub adversary: Adversary,
}

impl LocalTransport {
    pub fn new(relay: Arc<Relay>) -> LocalTransport {
        LocalTransport { relay, adversary: Adversary::default() }
    }

    pub fn hostile(relay: Arc<Relay>, adversary: Adversary) -> LocalTransport {
        LocalTransport { relay, adversary }
    }
}

impl Transport for LocalTransport {
    fn call(&mut self, _at: &Endpoint, request: &Request) -> Result<Response, RelayError> {
        let Request::Get { id, read, after } = request else {
            return self.relay.handle(request.clone());
        };
        let position = after + 1;
        let adversary = &self.adversary;
        let mut content = position;
        let dropped = adversary.drop.contains(&position);
        if dropped {
            content = position + 1;
        }
        for &(a, b) in &adversary.swap {
            if position == a {
                content = b;
            } else if position == b {
                content = a;
            }
        }
        if adversary.replay.iter().any(|&k| k + 1 == position) {
            content = position - 1;
        }
        match self.relay.handle(Request::Get { id: *id, read: *read, after: content - 1 })? {
            Response::Next(_, blob) => Ok(Response::Next(if dropped { content } else { position }, blob)),
            other => Ok(other),
        }
    }
}

/// A `Carrier` over a link. Ordered, because the relay numbers what it accepts.
pub struct RelayCarrier<T: Transport> {
    link: Link,
    transport: T,
    path: Option<PathBuf>,
}

impl RelayCarrier<TlsTransport> {
    /// Open the link described in `path`, over TLS pinned to the certificates the file names.
    pub fn open(path: &Path) -> Result<RelayCarrier<TlsTransport>, RelayError> {
        Ok(RelayCarrier { link: Link::load(path)?, transport: TlsTransport::new(), path: Some(path.to_path_buf()) })
    }

    /// Make a fresh queue on the relay at `address`, hold both halves of it, and write `path`.
    pub fn create(address: &str, path: &Path) -> Result<RelayCarrier<TlsTransport>, RelayError> {
        let (relay, pin) = parse_relay(address)?;
        let mut carrier = RelayCarrier::create_on(TlsTransport::new(), &relay, pin)?;
        carrier.path = Some(path.to_path_buf());
        carrier.link.save(path)?;
        Ok(carrier)
    }

    /// Point the link in `path` at another person's queue. A missing file becomes a link that
    /// only sends.
    pub fn join(path: &Path, invitation: &str) -> Result<Link, RelayError> {
        let mut link = if path.exists() { Link::load(path)? } else { Link::default() };
        link.join(invitation)?;
        link.save(path)?;
        Ok(link)
    }
}

impl<T: Transport> RelayCarrier<T> {
    pub fn new(link: Link, transport: T, path: Option<PathBuf>) -> RelayCarrier<T> {
        RelayCarrier { link, transport, path }
    }

    /// Make a fresh queue through `transport`, with both capabilities held: a link that sends
    /// and receives on one queue until `join` points `send` elsewhere.
    pub fn create_on(mut transport: T, relay: &str, pin: Pin) -> Result<RelayCarrier<T>, RelayError> {
        let at = Endpoint { relay: relay.to_string(), pin, id: random() };
        let (write, read): (Capability, Capability) = (random(), random());
        let request = Request::Create { id: at.id, write: hash_of(&write), read: hash_of(&read) };
        match transport.call(&at, &request)? {
            Response::Done => {}
            Response::Full => return Err(RelayError::Refused("the relay holds its maximum of queues")),
            _ => return Err(RelayError::Refused("the relay did not create the queue")),
        }
        let link = Link {
            send: Some(Half { at: at.clone(), capability: write }),
            receive: Some(Half { at, capability: read }),
            ..Link::default()
        };
        Ok(RelayCarrier { link, transport, path: None })
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    fn save(&self) -> Result<(), RelayError> {
        match &self.path {
            Some(path) => self.link.save(path),
            None => Ok(()),
        }
    }
}

fn io(e: RelayError) -> CarrierError {
    match e {
        RelayError::Io(e) => CarrierError::Io(e),
        RelayError::Disordered { expected, got } => CarrierError::Disordered { expected, got },
        RelayError::Refused(why) => CarrierError::Refused(why),
        other => CarrierError::Io(std::io::Error::other(other)),
    }
}

impl<T: Transport> Carrier for RelayCarrier<T> {
    fn put(&mut self, blob: &Blob) -> Result<(), CarrierError> {
        let send = self.link.send.clone().ok_or(CarrierError::Refused("this link has no queue to send on; join the other side's invitation"))?;
        let request = Request::Put { id: send.at.id, write: send.capability, blob: blob.clone() };
        match self.transport.call(&send.at, &request).map_err(io)? {
            Response::Seq(seq) => {
                if self.link.shared() {
                    self.link.wrote(seq);
                    self.save().map_err(io)?;
                }
                Ok(())
            }
            Response::Full => Err(CarrierError::Refused("the queue is full")),
            Response::TooFast => Err(CarrierError::Refused("the queue took its maximum this minute")),
            _ => Err(CarrierError::Refused("the relay refused the blob")),
        }
    }

    fn get(&mut self) -> Result<Blob, CarrierError> {
        let receive = self.link.receive.clone().ok_or(CarrierError::Refused("this link has no queue to receive on; make one with `unheld relay new`"))?;
        let was = self.link.after;
        self.link.skip_mine();
        let after = self.link.after;
        let request = Request::Get { id: receive.at.id, read: receive.capability, after };
        let result = match self.transport.call(&receive.at, &request).map_err(io)? {
            Response::Next(seq, blob) => {
                if seq != after + 1 {
                    return Err(CarrierError::Disordered { expected: after + 1, got: seq });
                }
                self.link.after = seq;
                Ok(blob)
            }
            Response::Nothing => Err(CarrierError::Empty),
            _ => Err(CarrierError::Refused("the relay refused the read")),
        };
        if self.link.after != was {
            self.save().map_err(io)?;
        }
        result
    }

    fn ordered(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Limits;
    use crate::tls::Identity;
    use std::net::TcpListener;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-relay-carrier-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn blob(i: u8) -> Blob {
        Blob::pad(&[i]).unwrap()
    }

    fn local(relay: &Arc<Relay>) -> LocalTransport {
        LocalTransport::new(Arc::clone(relay))
    }

    #[test]
    fn a_link_file_round_trips_and_an_invitation_names_where_which_and_one_right() {
        let dir = tmp("file");
        let at = Endpoint { relay: "relay.example:4443".into(), pin: Pin([5; 32]), id: [6; 32] };
        let mut link = Link {
            send: Some(Half { at: at.clone(), capability: [7; 32] }),
            receive: Some(Half { at, capability: [8; 32] }),
            after: 9,
            mine: BTreeSet::from([11, 12]),
        };
        link.save(&dir.join("q.json")).unwrap();
        assert_eq!(Link::load(&dir.join("q.json")).unwrap(), link);
        assert!(link.shared());

        let invitation = link.invitation().unwrap();
        assert!(invitation.starts_with("unheld-relay://relay.example:4443/0606"));
        assert!(invitation.contains("/0707"));
        assert_eq!(Half::parse(&invitation).unwrap(), link.send.clone().unwrap());
        assert!(Half::parse("https://relay.example/00/00#00").is_err());
        assert!(Half::parse(&format!("unheld-relay://relay.example:4443/{}#{}", hex(&[6; 32]), Pin([5; 32]).to_hex())).is_err());

        let other = Half { at: Endpoint { relay: "other.example:4443".into(), pin: Pin([1; 32]), id: [2; 32] }, capability: [3; 32] };
        link.join(&other.to_text()).unwrap();
        assert!(!link.shared());
        assert_eq!(link.invitation(), None);
        assert_eq!(link.send, Some(other));

        let (relay, pin) = parse_relay(&format!("unheld-relay://relay.example:4443#{}", Pin([5; 32]).to_hex())).unwrap();
        assert_eq!((relay.as_str(), pin), ("relay.example:4443", Pin([5; 32])));
        assert!(parse_relay("https://relay.example#00").is_err());
        assert!(parse_relay(&invitation).is_err());
    }

    #[test]
    fn over_tls_two_people_hold_two_queues_and_each_reads_only_what_the_other_wrote() {
        let dir = tmp("tls");
        let identity = Identity::generate("127.0.0.1").unwrap();
        let relay = Arc::new(Relay::open(&dir, Limits::default()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls = identity.server_config().unwrap();
        std::thread::spawn(move || crate::server::serve(listener, relay, tls));
        let address = format!("{}127.0.0.1:{port}#{}", config::SCHEME, identity.pin().to_hex());

        let (a, b) = (dir.join("a.json"), dir.join("b.json"));
        let invite_a = RelayCarrier::create(&address, &a).unwrap().link().invitation().unwrap();
        let invite_b = RelayCarrier::create(&address, &b).unwrap().link().invitation().unwrap();
        RelayCarrier::join(&a, &invite_b).unwrap();
        RelayCarrier::join(&b, &invite_a).unwrap();

        let mut alice = RelayCarrier::open(&a).unwrap();
        let mut bob = RelayCarrier::open(&b).unwrap();
        alice.put(&blob(1)).unwrap();
        alice.put(&blob(2)).unwrap();
        assert!(matches!(alice.get(), Err(CarrierError::Empty)), "a sender never sees its own blobs");
        assert_eq!(bob.get().unwrap(), blob(1));
        assert_eq!(bob.get().unwrap(), blob(2));
        assert!(matches!(bob.get(), Err(CarrierError::Empty)));
        bob.put(&blob(3)).unwrap();
        assert_eq!(alice.get().unwrap(), blob(3));
        assert_eq!(Link::load(&a).unwrap().after, 1);
        assert_eq!(Link::load(&b).unwrap().after, 2);
        assert!(alice.ordered());

        // Another holder of the same file starts where the file says.
        let mut again = RelayCarrier::open(&b).unwrap();
        alice.put(&blob(4)).unwrap();
        assert_eq!(again.get().unwrap(), blob(4));

        // A link that only sends refuses to read, and a client pinned to another certificate
        // fails in the handshake and reads nothing.
        let c = dir.join("c.json");
        RelayCarrier::join(&c, &invite_a).unwrap();
        let mut only_sends = RelayCarrier::open(&c).unwrap();
        assert!(matches!(only_sends.get(), Err(CarrierError::Refused(_))));
        only_sends.put(&blob(5)).unwrap();
        assert_eq!(alice.get().unwrap(), blob(5));
        let mut wrong = TlsTransport::new();
        let half = Link::load(&a).unwrap().receive.unwrap();
        let at = Endpoint { pin: Pin([0; 32]), ..half.at };
        assert!(wrong.call(&at, &Request::Get { id: at.id, read: half.capability, after: 0 }).is_err());
    }

    #[test]
    fn on_a_shared_queue_a_holder_skips_what_it_wrote_and_still_catches_a_drop() {
        let dir = tmp("shared");
        let relay = Arc::new(Relay::open(&dir, Limits::default()).unwrap());
        let mut alice = RelayCarrier::create_on(local(&relay), "local", Pin([0; 32])).unwrap();
        let shared = alice.link().clone();
        let mut bob = RelayCarrier::new(shared.clone(), local(&relay), None);

        // Alice writes 1 with nothing unread before it, so her cursor moves at once.
        alice.put(&blob(1)).unwrap();
        assert_eq!(alice.link().after, 1);
        // Bob writes 2 with 1 still unread, so 2 is remembered and passed when its turn comes.
        bob.put(&blob(2)).unwrap();
        assert_eq!(bob.link().after, 0);
        assert_eq!(bob.get().unwrap(), blob(1));
        assert!(matches!(bob.get(), Err(CarrierError::Empty)));
        assert_eq!(bob.link().after, 2);
        assert!(bob.link().mine.is_empty());
        assert_eq!(alice.get().unwrap(), blob(2));

        // Alice writes 3; a relay that drops 3 for bob serves 4 in its place, and bob's own 4,
        // waiting to be skipped, does not hide the hole (L12).
        alice.put(&blob(3)).unwrap();
        let mut bob = RelayCarrier::new(bob.link().clone(), LocalTransport::hostile(Arc::clone(&relay), Adversary { drop: vec![3], ..Adversary::default() }), None);
        bob.put(&blob(4)).unwrap();
        assert!(matches!(bob.get(), Err(CarrierError::Disordered { expected: 3, got: 4 })));
        let mut honest = RelayCarrier::new(bob.link().clone(), local(&relay), None);
        assert_eq!(honest.get().unwrap(), blob(3));
        assert!(matches!(honest.get(), Err(CarrierError::Empty)));
        assert_eq!(honest.link().after, 4);
    }

    #[test]
    fn a_relay_that_drops_is_caught_by_the_cursor_and_one_that_swaps_or_replays_is_left_to_the_core() {
        let dir = tmp("adversary");
        let relay = Arc::new(Relay::open(&dir, Limits::default()).unwrap());
        let mut writer = RelayCarrier::create_on(local(&relay), "local", Pin([0; 32])).unwrap();
        for i in 1..=4 {
            writer.put(&blob(i)).unwrap();
        }
        // A reader who wrote nothing: the receive half alone, from the start.
        let link = Link { receive: writer.link().receive.clone(), ..Link::default() };
        let reader = |after: u64, adversary: Adversary| {
            RelayCarrier::new(Link { after, ..link.clone() }, LocalTransport::hostile(Arc::clone(&relay), adversary), None)
        };

        let mut dropped = reader(0, Adversary { drop: vec![2], ..Adversary::default() });
        assert_eq!(dropped.get().unwrap(), blob(1));
        // Position 2 was dropped: the relay offers 3 as the next, the cursor refuses it (L12).
        assert!(matches!(dropped.get(), Err(CarrierError::Disordered { expected: 2, got: 3 })));
        assert!(matches!(dropped.put(&blob(9)), Err(CarrierError::Refused(_))), "a receive half cannot write");
        // The cursor did not move, so an honest relay later delivers 2.
        let mut honest = RelayCarrier::new(dropped.link().clone(), local(&relay), None);
        assert_eq!(honest.get().unwrap(), blob(2));

        // A swap keeps the numbers, so the carrier cannot see it: the content of 4 arrives as 3.
        // What makes that a fork, and a refusal, is the ratchet in the core (L16, L17).
        let mut swapped = reader(2, Adversary { swap: vec![(3, 4)], ..Adversary::default() });
        assert_eq!(swapped.get().unwrap(), blob(4));
        assert_eq!(swapped.get().unwrap(), blob(3));

        // A replay serves 1 again as 2; the core refuses a blob it opened once (L11).
        let mut replayed = reader(0, Adversary { replay: vec![1], ..Adversary::default() });
        assert_eq!(replayed.get().unwrap(), blob(1));
        assert_eq!(replayed.get().unwrap(), blob(1));
        assert_eq!(replayed.get().unwrap(), blob(3));
    }
}
