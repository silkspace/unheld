//! Any enrolment handed to a waiting device: it becomes bob or stays nobody.
#![no_main]
use libfuzzer_sys::fuzz_target;
use unheld_core::Enrolment;
use unheld_fuzz::world;

fuzz_target!(|data: &[u8]| {
    let mut w = world();
    if w.phone_one.join_device(&Enrolment(data.to_vec())).is_ok() {
        assert_eq!(w.phone_one.name().ok(), Some("bob"));
    }
});
