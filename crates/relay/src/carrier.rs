//! The client side: a `Carrier` over one queue, with the address, the capabilities and the read
//! cursor in a file of its own, never in the vault. A number out of sequence is an error before
//! the core sees the blob (L12). `LocalTransport` runs a relay in process, with an adversary at
//! the switches, so the carrier is tested against a relay that drops, swaps and replays.

use crate::config::{self, ID_LEN};
use crate::store::{hash_of, Relay};
use crate::tls::{client_config, Pin};
use crate::wire::{read_frame, write_frame, Capability, QueueId, Request, Response};
use crate::{hex, random, unhex, RelayError};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use unheld_blob::{Blob, Carrier, CarrierError};

/// One request, one answer, over whatever reaches the relay.
pub trait Transport {
    fn call(&mut self, request: &Request) -> Result<Response, RelayError>;
}

/// A queue as a person holds it. `write` is absent for a reader who may not append, `read` for a
/// writer who may not collect; `after` is the last number this holder has seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    pub relay: String,
    pub pin: Pin,
    pub id: QueueId,
    pub write: Option<Capability>,
    pub read: Option<Capability>,
    pub after: u64,
}

/// The file form. Every field is lower-case hex but the relay's `host:port` and the cursor.
#[derive(Serialize, Deserialize)]
struct QueueFile {
    relay: String,
    pin: String,
    queue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    write: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    read: Option<String>,
    #[serde(default)]
    after: u64,
}

impl Queue {
    /// `unheld-relay://host:port/<queue>#<pin>`, which says where and which, and not how.
    pub fn address(&self) -> String {
        format!("{}{}/{}#{}", config::SCHEME, self.relay, hex(&self.id), self.pin.to_hex())
    }

    /// A relay address with no queue: `unheld-relay://host:port#<pin>`, as `unheld-relay init` prints it.
    pub fn parse_relay(address: &str) -> Result<(String, Pin), RelayError> {
        let rest = address.strip_prefix(config::SCHEME).ok_or(RelayError::BadAddress)?;
        let (relay, pin) = rest.split_once('#').ok_or(RelayError::BadAddress)?;
        if relay.is_empty() || relay.contains('/') {
            return Err(RelayError::BadAddress);
        }
        Ok((relay.to_string(), Pin::parse(pin)?))
    }

    pub fn load(path: &Path) -> Result<Queue, RelayError> {
        let file: QueueFile = serde_json::from_slice(&std::fs::read(path)?).map_err(|_| RelayError::BadAddress)?;
        let cap = |s: Option<String>| -> Result<Option<Capability>, RelayError> {
            s.map(|s| unhex::<ID_LEN>(&s).ok_or(RelayError::BadAddress)).transpose()
        };
        Ok(Queue {
            relay: file.relay,
            pin: Pin::parse(&file.pin)?,
            id: unhex::<ID_LEN>(&file.queue).ok_or(RelayError::BadAddress)?,
            write: cap(file.write)?,
            read: cap(file.read)?,
            after: file.after,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), RelayError> {
        let file = QueueFile {
            relay: self.relay.clone(),
            pin: self.pin.to_hex(),
            queue: hex(&self.id),
            write: self.write.as_ref().map(|c| hex(c)),
            read: self.read.as_ref().map(|c| hex(c)),
            after: self.after,
        };
        let text = serde_json::to_string_pretty(&file).map_err(|_| RelayError::BadAddress)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

/// A connection to a relay that trusts one pin, reopened when it breaks.
pub struct TlsTransport {
    relay: String,
    config: Arc<ClientConfig>,
    stream: Option<StreamOwned<ClientConnection, TcpStream>>,
}

impl TlsTransport {
    pub fn new(relay: &str, pin: Pin) -> Result<TlsTransport, RelayError> {
        Ok(TlsTransport { relay: relay.to_string(), config: client_config(pin)?, stream: None })
    }

    fn connect(&mut self) -> Result<&mut StreamOwned<ClientConnection, TcpStream>, RelayError> {
        if self.stream.is_none() {
            let host = self.relay.rsplit_once(':').map(|(h, _)| h).unwrap_or(&self.relay);
            let name = ServerName::try_from(host.to_string()).map_err(|_| RelayError::BadAddress)?;
            let tcp = TcpStream::connect(&self.relay)?;
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(config::limits::SILENCE_SECS)))?;
            let conn = ClientConnection::new(Arc::clone(&self.config), name)?;
            self.stream = Some(StreamOwned::new(conn, tcp));
        }
        Ok(self.stream.as_mut().expect("just set"))
    }
}

impl Transport for TlsTransport {
    fn call(&mut self, request: &Request) -> Result<Response, RelayError> {
        let result = (|| {
            let stream = self.connect()?;
            write_frame(stream, &request.encode())?;
            Response::decode(&read_frame(stream)?)
        })();
        if result.is_err() {
            self.stream = None;
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

/// A relay in this process, reached directly, with an adversary in the way.
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
    fn call(&mut self, request: &Request) -> Result<Response, RelayError> {
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

/// A `Carrier` over one queue. Ordered, because the relay numbers what it accepts.
pub struct RelayCarrier<T: Transport> {
    queue: Queue,
    transport: T,
    path: Option<PathBuf>,
}

impl RelayCarrier<TlsTransport> {
    /// Open the queue described in `path`, over TLS pinned to the certificate the file names.
    pub fn open(path: &Path) -> Result<RelayCarrier<TlsTransport>, RelayError> {
        let queue = Queue::load(path)?;
        let transport = TlsTransport::new(&queue.relay, queue.pin)?;
        Ok(RelayCarrier { queue, transport, path: Some(path.to_path_buf()) })
    }

    /// Make a fresh queue on the relay at `address` and write it to `path`.
    pub fn create(address: &str, path: &Path) -> Result<RelayCarrier<TlsTransport>, RelayError> {
        let (relay, pin) = Queue::parse_relay(address)?;
        let transport = TlsTransport::new(&relay, pin)?;
        let mut carrier = RelayCarrier::create_on(transport, &relay, pin)?;
        carrier.path = Some(path.to_path_buf());
        carrier.queue.save(path)?;
        Ok(carrier)
    }
}

impl<T: Transport> RelayCarrier<T> {
    pub fn new(queue: Queue, transport: T, path: Option<PathBuf>) -> RelayCarrier<T> {
        RelayCarrier { queue, transport, path }
    }

    /// Make a fresh queue, with both capabilities, through `transport`.
    pub fn create_on(mut transport: T, relay: &str, pin: Pin) -> Result<RelayCarrier<T>, RelayError> {
        let queue = Queue { relay: relay.to_string(), pin, id: random(), write: Some(random()), read: Some(random()), after: 0 };
        let request = Request::Create {
            id: queue.id,
            write: hash_of(queue.write.as_ref().expect("set")),
            read: hash_of(queue.read.as_ref().expect("set")),
        };
        match transport.call(&request)? {
            Response::Done => Ok(RelayCarrier { queue, transport, path: None }),
            Response::Full => Err(RelayError::Refused("the relay holds its maximum of queues")),
            _ => Err(RelayError::Refused("the relay did not create the queue")),
        }
    }

    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    fn save(&self) -> Result<(), RelayError> {
        match &self.path {
            Some(path) => self.queue.save(path),
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
        let write = self.queue.write.ok_or(CarrierError::Refused("this queue is held to read, not to write"))?;
        match self.transport.call(&Request::Put { id: self.queue.id, write, blob: blob.clone() }).map_err(io)? {
            Response::Seq(_) => Ok(()),
            Response::Full => Err(CarrierError::Refused("the queue is full")),
            Response::TooFast => Err(CarrierError::Refused("the queue took its maximum this minute")),
            _ => Err(CarrierError::Refused("the relay refused the blob")),
        }
    }

    fn get(&mut self) -> Result<Blob, CarrierError> {
        let read = self.queue.read.ok_or(CarrierError::Refused("this queue is held to write, not to read"))?;
        let after = self.queue.after;
        match self.transport.call(&Request::Get { id: self.queue.id, read, after }).map_err(io)? {
            Response::Next(seq, blob) => {
                if seq != after + 1 {
                    return Err(CarrierError::Disordered { expected: after + 1, got: seq });
                }
                self.queue.after = seq;
                self.save().map_err(io)?;
                Ok(blob)
            }
            Response::Nothing => Err(CarrierError::Empty),
            _ => Err(CarrierError::Refused("the relay refused the read")),
        }
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

    #[test]
    fn a_queue_file_round_trips_and_its_address_names_where_and_which() {
        let dir = tmp("file");
        let queue = Queue { relay: "relay.example:4443".into(), pin: Pin([5; 32]), id: [6; 32], write: Some([7; 32]), read: None, after: 9 };
        queue.save(&dir.join("q.json")).unwrap();
        assert_eq!(Queue::load(&dir.join("q.json")).unwrap(), queue);
        assert!(queue.address().starts_with("unheld-relay://relay.example:4443/0606"));
        let (relay, pin) = Queue::parse_relay(&format!("unheld-relay://relay.example:4443#{}", Pin([5; 32]).to_hex())).unwrap();
        assert_eq!((relay.as_str(), pin), ("relay.example:4443", Pin([5; 32])));
        assert!(Queue::parse_relay("https://relay.example#00").is_err());
        assert!(Queue::parse_relay(&queue.address()).is_err());
    }

    #[test]
    fn over_tls_a_blob_goes_in_numbered_and_comes_out_in_order_and_a_wrong_pin_never_connects() {
        let dir = tmp("tls");
        let identity = Identity::generate("127.0.0.1").unwrap();
        let relay = Arc::new(Relay::open(&dir, Limits::default()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls = identity.server_config().unwrap();
        std::thread::spawn(move || crate::server::serve(listener, relay, tls));
        let address = format!("{}127.0.0.1:{port}#{}", config::SCHEME, identity.pin().to_hex());

        let path = dir.join("queue.json");
        let mut writer = RelayCarrier::create(&address, &path).unwrap();
        writer.put(&blob(1)).unwrap();
        writer.put(&blob(2)).unwrap();

        let mut reader = RelayCarrier::open(&path).unwrap();
        assert_eq!(reader.get().unwrap(), blob(1));
        assert_eq!(reader.get().unwrap(), blob(2));
        assert!(matches!(reader.get(), Err(CarrierError::Empty)));
        assert_eq!(Queue::load(&path).unwrap().after, 2);
        assert!(reader.ordered());

        // Another holder of the same file starts where the file says.
        let mut again = RelayCarrier::open(&path).unwrap();
        writer.put(&blob(3)).unwrap();
        assert_eq!(again.get().unwrap(), blob(3));

        // A client pinned to another certificate fails in the handshake and reads nothing.
        let mut wrong = TlsTransport::new(&format!("127.0.0.1:{port}"), Pin([0; 32])).unwrap();
        let q = writer.queue();
        assert!(wrong.call(&Request::Get { id: q.id, read: q.read.unwrap(), after: 0 }).is_err());
    }

    #[test]
    fn a_relay_that_drops_is_caught_by_the_cursor_and_one_that_swaps_or_replays_is_left_to_the_core() {
        let dir = tmp("adversary");
        let relay = Arc::new(Relay::open(&dir, Limits::default()).unwrap());
        let mut writer = RelayCarrier::create_on(LocalTransport::new(Arc::clone(&relay)), "local", Pin([0; 32])).unwrap();
        for i in 1..=4 {
            writer.put(&blob(i)).unwrap();
        }
        let queue = writer.queue().clone();

        let adversary = Adversary { drop: vec![2], swap: vec![(3, 4)], replay: vec![] };
        let mut reader = RelayCarrier::new(queue.clone(), LocalTransport::hostile(Arc::clone(&relay), adversary), None);
        assert_eq!(reader.get().unwrap(), blob(1));
        // Position 2 was dropped: the relay offers 3 as the next, the cursor refuses it (L12).
        assert!(matches!(reader.get(), Err(CarrierError::Disordered { expected: 2, got: 3 })));
        // The cursor did not move, so an honest relay later delivers 2.
        let mut honest = RelayCarrier::new(Queue { after: reader.queue().after, ..queue.clone() }, LocalTransport::new(Arc::clone(&relay)), None);
        assert_eq!(honest.get().unwrap(), blob(2));

        // A swap keeps the numbers, so the carrier cannot see it: the content of 4 arrives as 3.
        // What makes that a fork, and a refusal, is the ratchet in the core (L16, L17).
        let adversary = Adversary { drop: vec![], swap: vec![(3, 4)], replay: vec![] };
        let mut swapped = RelayCarrier::new(Queue { after: 2, ..queue.clone() }, LocalTransport::hostile(Arc::clone(&relay), adversary), None);
        assert_eq!(swapped.get().unwrap(), blob(4));
        assert_eq!(swapped.get().unwrap(), blob(3));

        // A replay serves 1 again as 2; the core refuses a blob it opened once (L11).
        let adversary = Adversary { drop: vec![], swap: vec![], replay: vec![1] };
        let mut replayed = RelayCarrier::new(queue, LocalTransport::hostile(relay, adversary), None);
        assert_eq!(replayed.get().unwrap(), blob(1));
        assert_eq!(replayed.get().unwrap(), blob(1));
        assert_eq!(replayed.get().unwrap(), blob(3));
    }
}
