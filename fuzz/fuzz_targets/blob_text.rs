//! Text and bytes from any carrier: a blob is a bucket or refused, and reading it never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_blob::{config, Blob};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(blob) = Blob::from_text(text) {
            assert!(config::BUCKETS.contains(&blob.len()));
            let _ = blob.unpad();
            let _ = unheld_core::inspect(&blob);
        }
    }
    if let Ok(blob) = Blob::from_bytes(data.to_vec()) {
        let _ = blob.unpad();
        let _ = unheld_core::inspect(&blob);
    }
});
