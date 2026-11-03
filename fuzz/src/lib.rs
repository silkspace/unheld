//! One world for every target: two verified peers with a session, a third peer whose first
//! message is still unopened, and two of bob's devices mid-enrolment. Built once on disk, with
//! one real object of each kind a target reads written beside it; every process then starts
//! from a copy, so the seeds stay the seeds.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use unheld_blob::Blob;
use unheld_core::{Core, Intro, Share};

pub const PASSPHRASE: &str = "fuzz";
pub const ALICE: &str = "alice";
pub const CAROL: &str = "carol";

/// What each seed file is called, under `seeds/` in the world directory.
pub const SEED_NAMES: [&str; 6] = ["welcome", "message", "intro", "enrolment", "attach", "shares"];

pub struct World {
    pub bob: Core,
    /// Bob's device, enrolled by bob, waiting for the enrolment.
    pub phone_one: Core,
    pub bob_prefix: String,
}

/// Where the pristine world lives: `fuzz/world`, or `UNHELD_FUZZ_WORLD`.
pub fn world_dir() -> PathBuf {
    std::env::var_os("UNHELD_FUZZ_WORLD")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("world"))
}

fn fresh(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Create the world and its seeds under `root` if they are not there yet.
pub fn ensure_world(root: &Path) {
    if root.join("seeds").join("shares").exists() {
        return;
    }
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("seeds")).expect("world dir");

    let mut alice = Core::create(&fresh(root, "alice"), PASSPHRASE, ALICE).expect("alice");
    let mut bob = Core::create(&fresh(root, "bob"), PASSPHRASE, "bob").expect("bob");
    let mut carol = Core::create(&fresh(root, "carol"), PASSPHRASE, CAROL).expect("carol");

    let intro = alice.intro().expect("intro");
    bob.import(ALICE, &intro).expect("import alice");
    alice.import("bob", &bob.intro().expect("intro")).expect("import bob");
    bob.verify(ALICE, true).expect("verify");
    alice.verify("bob", true).expect("verify");
    bob.open(&alice.seal("bob", b"one").expect("seal")).expect("open");
    let message = alice.seal("bob", b"two").expect("seal");

    bob.import(CAROL, &carol.intro().expect("intro")).expect("import carol");
    carol.import("bob", &bob.intro().expect("intro")).expect("import bob");
    bob.verify(CAROL, true).expect("verify");
    carol.verify("bob", true).expect("verify");
    let welcome = carol.seal("bob", b"hello").expect("seal");

    let (_phone_one, request_one) = Core::create_device(&fresh(root, "phone-one"), PASSPHRASE).expect("device");
    let enrolment = bob.enroll("phone-one", &request_one, true).expect("enroll");
    let (mut phone_two, request_two) = Core::create_device(&fresh(root, "phone-two"), PASSPHRASE).expect("device");
    let enrolment_two = bob.enroll("phone-two", &request_two, true).expect("enroll");
    let attach = phone_two.join_device(&enrolment_two).expect("join");

    let shares = bob.split(2, 3).expect("split");
    let mut share_bytes = Vec::new();
    for s in shares.iter().take(2) {
        share_bytes.extend_from_slice(&decode(&s.to_text()));
    }

    let seeds: [(&str, Vec<u8>); 6] = [
        ("welcome", welcome.as_bytes().to_vec()),
        ("message", message.as_bytes().to_vec()),
        ("intro", intro.0),
        ("enrolment", enrolment.0),
        ("attach", attach.0),
        ("shares", share_bytes),
    ];
    for (name, bytes) in seeds {
        std::fs::write(root.join("seeds").join(name), bytes).expect("seed");
    }
}

/// A seed by name, from the world directory.
pub fn seed(name: &str) -> Vec<u8> {
    std::fs::read(world_dir().join("seeds").join(name)).expect("seed; run the seeds binary first")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("copy dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

fn load() -> World {
    let pristine = world_dir();
    ensure_world(&pristine);
    let mine = std::env::temp_dir().join(format!("unheld-fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mine);
    copy_dir(&pristine, &mine);
    let bob = Core::unlock(&mine.join("bob"), PASSPHRASE).expect("bob");
    let phone_one = Core::unlock(&mine.join("phone-one"), PASSPHRASE).expect("phone one");
    let bob_prefix = bob.own_fingerprint_prefix().expect("prefix");
    World { bob, phone_one, bob_prefix }
}

fn decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text.trim()).expect("base64")
}

static WORLD: OnceLock<Mutex<World>> = OnceLock::new();

pub fn world() -> MutexGuard<'static, World> {
    WORLD.get_or_init(|| Mutex::new(load())).lock().unwrap_or_else(|e| e.into_inner())
}

/// A directory for a vault a target may create; emptied first.
pub fn scratch(name: &str) -> PathBuf {
    fresh(&std::env::temp_dir(), &format!("unheld-fuzz-{}-{}", name, std::process::id()))
}

/// Bytes as a blob: taken whole when they are a bucket, padded into one otherwise.
pub fn blob_of(data: &[u8]) -> Option<Blob> {
    Blob::from_bytes(data.to_vec()).ok().or_else(|| Blob::pad(data).ok())
}

/// Two shares from one input, split down the middle.
pub fn two_shares(data: &[u8]) -> Option<[Share; 2]> {
    use base64::Engine as _;
    let (a, b) = data.split_at(data.len() / 2);
    let enc = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
    Some([Share::from_text(&enc(a)).ok()?, Share::from_text(&enc(b)).ok()?])
}

pub fn intro_of(data: &[u8]) -> Intro {
    Intro(data.to_vec())
}
