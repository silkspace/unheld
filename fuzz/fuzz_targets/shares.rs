//! Any two shares: they rebuild bob's identity and nothing else, or they are refused.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_core::Core;
use unheld_fuzz::{scratch, two_shares, world, PASSPHRASE};

fuzz_target!(|data: &[u8]| {
    let Some(shares) = two_shares(data) else { return };
    let w = world();
    let dir = scratch("recovered");
    if let Ok(core) = Core::recover(&dir, PASSPHRASE, "bob", &shares) {
        assert_eq!(core.own_fingerprint_prefix().ok(), Some(w.bob_prefix.clone()));
    }
    let _ = std::fs::remove_dir_all(&dir);
});
