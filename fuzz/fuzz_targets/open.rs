//! Anything the carrier delivers: `open` refuses or opens, never panics, and what opens is
//! from a peer bob verified.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_core::vocab::MemberTrust;
use unheld_fuzz::{blob_of, world, ALICE, CAROL};

fuzz_target!(|data: &[u8]| {
    let Some(blob) = blob_of(data) else { return };
    let mut w = world();
    if let Ok(opened) = w.bob.open(&blob) {
        for o in opened {
            assert!(o.from == ALICE || o.from == CAROL, "opened from {}", o.from);
            assert_eq!(o.trust, MemberTrust::Verified);
        }
    }
});
