//! Any attach handed back to the witness: a device of bob's reaches every session, or nothing does.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_core::Attach;
use unheld_fuzz::world;

fuzz_target!(|data: &[u8]| {
    let mut w = world();
    let _ = w.bob.connect_device(&Attach(data.to_vec()));
});
