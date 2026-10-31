//! The structural laws as tests over the source tree (KERNEL.md L2, AGENTS.md rule 6).

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|_| panic!("missing {rel}"))
}

/// L2: the carriers crate cannot depend on the core, so no carrier can name a key or a session.
#[test]
fn carriers_cannot_depend_on_core() {
    let manifest = read("crates/carriers/Cargo.toml");
    assert!(!manifest.contains("unheld-core"), "carriers crate depends on unheld-core");
    assert!(!manifest.contains("openmls"), "carriers crate depends on an MLS crate");
    let src = read("crates/carriers/src/lib.rs");
    for word in ["Session", "SignatureKeyPair", "MlsGroup", "passphrase"] {
        assert!(!src.contains(word), "carriers source mentions {word}");
    }
}

/// L2 also for the blob crate: the adversary's objects know nothing but bytes.
#[test]
fn blob_crate_depends_on_nothing_secret() {
    let manifest = read("crates/blob/Cargo.toml");
    for forbidden in ["unheld-core", "openmls", "argon2", "chacha20poly1305"] {
        assert!(!manifest.contains(forbidden), "blob crate depends on {forbidden}");
    }
}

/// Rule 6: no unsafe anywhere in the workspace.
#[test]
fn every_crate_forbids_unsafe() {
    for rel in ["crates/blob/src/lib.rs", "crates/core/src/lib.rs", "crates/carriers/src/lib.rs", "crates/cli/src/main.rs"] {
        assert!(read(rel).starts_with("#![forbid(unsafe_code)]"), "{rel} does not forbid unsafe");
    }
}

/// Rule 4: no telemetry, analytics or remote-configuration dependency may appear in the lock file.
#[test]
fn lockfile_has_no_telemetry() {
    let lock = read("Cargo.lock");
    for forbidden in ["sentry", "opentelemetry", "segment", "mixpanel", "launchdarkly", "firebase"] {
        assert!(!lock.contains(&format!("name = \"{forbidden}")), "lock file contains {forbidden}");
    }
}

/// Rule 10: no marketing words anywhere in the tree.
#[test]
fn no_marketing_words() {
    for rel in ["README.md", "IDEA.md", "KERNEL.md", "docs/CLI.md", "docs/MCP.md", "docs/INTEGRATION.md"] {
        let text = read(rel).to_lowercase();
        for word in ["unhackable", "military grade", "military-grade"] {
            assert!(!text.contains(word), "{rel} contains {word:?}");
        }
    }
}
