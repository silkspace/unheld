//! Serve queues over pinned TLS: one thread per connection, one frame per request, and a sweep
//! of idle queues on a clock. A connection that sends something unreadable is answered `Bad`
//! and closed; one that falls silent is closed.

use crate::config::limits;
use crate::store::Relay;
use crate::wire::{read_frame, write_frame, Request, Response};
use crate::RelayError;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Accept connections forever. Returns only if the listener fails.
pub fn serve(listener: TcpListener, relay: Arc<Relay>, tls: Arc<ServerConfig>) -> Result<(), RelayError> {
    let sweeper = Arc::clone(&relay);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3600));
        let _ = sweeper.sweep(SystemTime::now());
    });
    for stream in listener.incoming() {
        let stream = stream?;
        let relay = Arc::clone(&relay);
        let tls = Arc::clone(&tls);
        std::thread::spawn(move || {
            let _ = connection(stream, &relay, tls);
        });
    }
    Ok(())
}

fn connection(tcp: TcpStream, relay: &Relay, tls: Arc<ServerConfig>) -> Result<(), RelayError> {
    let silence = Some(Duration::from_secs(limits::SILENCE_SECS));
    tcp.set_read_timeout(silence)?;
    tcp.set_write_timeout(silence)?;
    let mut stream = StreamOwned::new(ServerConnection::new(tls)?, tcp);
    loop {
        let body = match read_frame(&mut stream) {
            Ok(body) => body,
            Err(RelayError::Malformed) => {
                write_frame(&mut stream, &Response::Bad.encode())?;
                return Err(RelayError::Malformed);
            }
            Err(e) => return Err(e),
        };
        let response = match Request::decode(&body) {
            Ok(request) => relay.handle(request)?,
            Err(_) => Response::Bad,
        };
        write_frame(&mut stream, &response.encode())?;
        if response == Response::Bad {
            return Err(RelayError::Malformed);
        }
    }
}
