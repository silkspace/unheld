//! Any introduction handed over out of band: staged as Pending or refused, never verified.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_core::vocab::PeerState;
use unheld_fuzz::{intro_of, world};

fuzz_target!(|data: &[u8]| {
    let mut w = world();
    if let Ok(peer) = w.bob.import("mallory", &intro_of(data)) {
        assert_ne!(peer.state, PeerState::Verified);
    }
});
