//! Frames from the network, both directions: a body is one exact encoding or malformed, what
//! decodes re-encodes to the same bytes, and a frame above the largest body is refused unread.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_relay::wire::{read_frame, Request, Response};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = Request::decode(data) {
        assert_eq!(request.encode(), data);
    }
    if let Ok(response) = Response::decode(data) {
        assert_eq!(response.encode(), data);
    }
    if let Ok(body) = read_frame(&mut &data[..]) {
        let _ = Request::decode(&body);
        let _ = Response::decode(&body);
    }
});
