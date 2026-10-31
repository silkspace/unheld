# AGENTS.md: how to work on unheld

Read this before changing anything. IDEA.md says what we are building and why, CLAUDE.md is the map of the code and the commands, and this file is the taste the code is built with and the rules an agent is held to. The project is a communications platform whose users may be in real danger if we get something wrong, so the bar is higher than for ordinary software, and the rules below are checked by tests, not remembered by people.

## The rules that cannot be bent

1. **Never write a cryptographic primitive.** No hash, cipher, key agreement, ratchet, signature, random number generator or padding scheme is written in this repository, ever, not as a prototype, not as a learning exercise, not behind a feature flag. Every primitive comes from the libraries named in IDEA.md (libsignal, OpenMLS, Arti, libsodium or RustCrypto) and a test fails when a file outside the `vendor` boundary implements one. If you believe a primitive is missing, write a design note in `docs/decisions/` that names the vetted library that provides it and stop there.

2. **Plaintext and keys never leave the core.** The Rust core exposes a narrow typed API and nothing that crosses it is a private key, a session state or a message plaintext bound for anything but the renderer. No plaintext is ever logged, printed, serialised to disk unencrypted, included in an error message, sent to a test fixture file or pasted into chat. A `Debug` impl on a key type prints a fingerprint, never the bytes. A test fails when a type holding secret material derives `Debug`, `Serialize` or `Clone` without a redacting wrapper.

3. **The relay is the adversary.** Any code that runs on a relay is written as though a hostile party runs it, and any code in the client treats every relay response as an attack until authenticated. Adversarial tests in `tests/adversarial/` run a malicious relay against the client and must stay green. A change that makes the relay hold one more fact about a user is refused unless the design note explains why the threat model allows it.

4. **No telemetry, no third-party SDKs, no vendor push payloads.** No analytics, crash reporting, advertising, attribution, feature-flag or remote-configuration dependency enters any client. Push notifications, where they exist at all, carry a wake signal and nothing else. A test reads the lock files and fails on any dependency from a denylist, and every new dependency is justified in its pull request by name, licence, maintainer, audit status and why the standard library or an existing dependency does not do the job.

5. **Dependencies are pinned, minimal and audited.** `cargo vet` or `cargo crev` records a review for every crate that touches a key or a plaintext, `cargo deny` enforces the licence and advisory policy, and Python tooling under UV uses a committed lock file. Upgrading a cryptographic dependency is its own commit with the changelog read and summarised.

6. **Memory safety is the floor.** Code that touches secrets is Rust with `#![forbid(unsafe_code)]` except in a named, audited FFI module. Secret material lives in types that zeroise on drop. Constant-time comparison is used for every secret comparison and a test greps for `==` on key types.

7. **Metadata is content.** Nothing is added to a message, an envelope or a relay request that was not already there without a design note on what an observer learns from it. Message sizes come from the fixed bucket set in config, send times are jittered by code the model cannot reach, and receipts, presence and typing indicators default off per contact.

8. **Builds are reproducible.** A release that cannot be rebuilt byte for byte from its tag by a second machine is not a release. The build script, the toolchain version and the transparency log entry are part of the release commit.

9. **Fail closed.** A missing config value, an unverified key, an unknown relay, a failed signature check or a ciphertext of an unexpected size results in refusal and a typed error, never a fallback to something weaker. There is no "insecure mode" and no environment variable that disables a check.

10. **Say what we do not protect.** User-facing text, documentation and this repository state plainly that a compromised device, a hostile correspondent and a coerced user are outside what the system can defend. Marketing language ("unhackable", "military grade", "100% secure") does not appear anywhere and a test greps for it.

## The production rules

Eight rules every crate is held to, and `crates/cli/tests/rules.rs` checks the structural ones on every test run.

- **Typed interfaces.** Every public function, API and wire message is a typed struct or enum with `serde` derives at the wire edge and validation on deserialisation; a `serde_json::Value`, a `HashMap<String, String>` or a `Vec<u8>` in a public signature that is not explicitly a ciphertext type is a bug. On the Python side that means pydantic models and `Literal` for closed sets.
- **Never cut context at a fixed length.** Message history, contact lists and relay queue listings are paged with a cursor and a total; nothing is truncated to a literal. Padding to a fixed bucket is not truncation and is marked `// pad-ok:` where it happens.
- **factory(config) → behaviour.** A transport, a relay kind, a storage backend or a ciphersuite is a registry entry built from typed configuration, never a branch on a name.
- **Field descriptions on everything.** Wire types, config structs and Python models carry a description on every field, because the protocol specification is generated from them.
- **No hand-rolled infrastructure.** Configuration comes through one typed config module (`config.rs` with `figment` or equivalent, `pydantic-settings` in Python), and serialisation, dates, retries and TLS come from maintained libraries. The one thing we hand-roll is the architecture, and never the parts.
- **Models decide, code enforces.** No language model is in the runtime path of this product at all. In development, an agent proposes and a human merges; an agent never has a signing key, a release credential, a relay's deploy token or a user's data, and the repository has no tool that grants one.
- **All constants in one config module.** Bucket sizes, jitter windows, queue rotation intervals, expiry defaults, relay lists, ciphersuite identifiers and file names live in `config.rs` and `vocab.rs` (or their Python twins), and logic never carries a literal other than 0, 1 and -1.
- **No string matching that drifts.** No behaviour depends on comparing a string spelled in logic; relay kinds, message kinds and error kinds are enums, and a vendor's error text is never parsed.

## How to work

**Design before code for anything near a key.** A change to identity, sessions, queues, transport, storage format or the linked-device flow starts as a short note in `docs/decisions/NNN-title.md` with the threat model rows it touches, what an attacker at each tier learns before and after, which vetted library carries the cryptography, and the square from KERNEL.md: the morphism the adversary can insert and the composite that becomes `Refuse`. A change whose square commutes for the adversary is refused. The note is reviewed before the code is written. A pure refactor, a test, a documentation fix or a client interface change does not need one.

**Read first, commit small, test the real behaviour.** Read the file and its tests before editing. Stage specific files and never `git add -A`. One topical commit per change with a message that says what changed and why in a sentence. Run the test suite, the adversarial suite and the rule checks before asking for review, and wait for the owner's confirmation before pushing.

**Cite the law.** Every pull request names the TRACE.md row of each law it touches, and a change that touches no law says so, because a change that cannot be traced to the kernel is either a refactor or a feature that does not belong.

**Red-team your own change.** Before marking a change ready, write down in the pull request the strongest attack you can think of against it and what the tests do about it. If the answer is "nothing", add the test or do not ship.

**Test adversarially, not just happily.** Every protocol feature has a test where the other side is malicious: a relay that replays, reorders, drops or substitutes blobs; a contact who sends malformed ciphertext; a linked device that lies about its identity. Fuzz targets exist for every parser of untrusted bytes.

**The owner's credentials, keys and infrastructure are theirs.** Give the command, never handle the secret. This includes you: an assistant with a shell never holds a signing key, a release credential, a deploy token or a forge token with merge rights, and every commit it writes is read by a human before a human's hardware key signs the merge (`docs/MAINTAINERS.md`). Relay deploy tokens, release signing keys and transparency log credentials are never in the repository, in a chat, or on a machine an agent operates.

**Report outcomes exactly.** If tests fail, say so and show the output. If a step was skipped, say which. If a security property is only partly achieved, say what is missing in the same sentence that says what works. Overstating what the code protects is a bug of the same class as a weak cipher.

## Things that will bite us (keep them fixed)

- **Reproducible builds break silently.** A new dependency with a build script that embeds a timestamp, or a toolchain bump, breaks reproducibility without a test failing; the release check rebuilds on a second runner and compares hashes, and it stays in CI.
- **"Just for the demo" is forever.** A direct TLS path with no padding "for now", a debug flag that prints a plaintext, a relay that logs IPs to diagnose a problem: each becomes the default by the time anyone notices. Do not add them; add a test fixture instead.
- **The renderer is the attack surface.** Anything that turns bytes into pixels (text layout, images, link previews, emoji) has been the entry point for most real-world messenger exploits. The renderer runs in its own sandbox with no network and no key access, link previews are off, and media is decoded by a hardened library or not at all.
- **Linked devices are how Signal got phished.** Adding a device always requires a confirmation on an existing device, shows the new device's fingerprint there, and never works from a single scanned code.
- **Python is for tooling only.** Nothing that touches a key or a plaintext is written in Python here. Python under UV runs simulations of traffic analysis, documentation generation and release tooling, and that is all.

## Commits

How a commit is written and pushed.

- **A commit message states the goal and the change, never the process.** Nothing about what was tried, reconsidered, overlooked or fixed along the way, nothing about who or what wrote the code, and no mention of an assistant. The subject line is under seventy-two characters and names the change; the body is full sentences saying what is now true and why it matters, in the project's own voice (for unheld, the type signature and the law it serves).
- **Stage by name.** Never `git add -A` or `git add .`; one topical commit per change, with the files listed.
- **Commits are signed.** This machine signs with SSH: `git config --global gpg.format ssh`, `git config --global user.signingkey ~/.ssh/id_ed25519.pub`, `git config --global commit.gpgsign true`. The `--global` flag writes user-level config and can be run from any directory. The same public key is added on GitHub as a signing key, separately from its authentication role, so commits show as verified. A hardware-backed key replaces the laptop key when one exists.
- **Long messages go through a file.** Write the message to `.git/COMMIT_MSG` and commit with `-F .git/COMMIT_MSG`, so it is read as text before it is permanent.
- **Test, then wait, then push.** Run the suite, show the result, and push only after the owner confirms. A first push to an empty remote creates the branch: `git init -b main`, `git remote add origin <url>`, `git push -u origin main`.
- **Scan before the push publishes.** A push makes every document public, so before it, read the tree for process narrative and bot voice (staccato fragments, parallel triples, em-dashes, "first draft", "overlooked", "honestly") and fix the documents, not just the message.
