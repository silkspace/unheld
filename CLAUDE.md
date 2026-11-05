# CLAUDE.md

Guidance for Claude Code when working in this repository. AGENTS.md holds the rules and must be read before any change; IDEA.md holds the threat model and the design and must be read before any change near identity, sessions, queues, transport or storage. KERNEL.md is the whole system as one signature with its laws, TRACE.md maps every law to a phase, a test, a review layer and a client screen, OATH.md is what the maintainers promise, and `docs/MAINTAINERS.md` is how they keep their own machines and keys. Every pull request cites the TRACE.md row of each law it touches. Python, where it appears, is managed with UV only; commits stage files by name; nothing is pushed before tests pass and the owner confirms.

## What this is

A communications platform designed from a written threat model (IDEA.md) rather than from a feature list. The cryptography is entirely borrowed from vetted libraries, and what we build is the architecture around it: keypair-only identity with no directory, per-contact unidirectional queues on relays that anyone can run and that hold nothing, onion-routed transport by default, padded and jittered traffic, Messaging Layer Security for groups, local-only encrypted storage, reproducible builds with a transparency log, and a linked-device flow that cannot be phished with a single QR code.

## Non-negotiables in one breath

No cryptographic primitive is written here. No plaintext or key crosses the core's API, appears in a log, an error, a fixture or a chat. The relay is treated as hostile. No telemetry or third-party SDK enters a client. Everything fails closed. Nothing that touches a secret is written in anything but Rust; the Python module is that Rust compiled for the interpreter, and Python itself is for its tests and for tooling. Any change near a key starts as a design note in `docs/decisions/` before code.

## Layout (planned; create as phases land)

```
unheld/
  IDEA.md                 threat model, principles, architecture, roadmap
  KERNEL.md               the signature, the laws, the language, the inflation order
  TRACE.md                law → phase → test → review layer → client screen; the MVP criteria; known gaps
  OATH.md                 the maintainers' commitment, signed with release keys
  AGENTS.md               how to work here, the rules, what bit us
  CLAUDE.md               this file
  docs/
    threat-model.md       the tiers from IDEA.md, kept current as the source of truth
    MAINTAINERS.md        keys, machines, agents, dependencies, disclosure, release checklist
    CLI.md MCP.md INTEGRATION.md   the three client surfaces
    protocol/             queue and relay wire specification, generated from wire types
    decisions/            NNN-title.md design notes, one per decision near a key
  Cargo.toml              the workspace
  crates/blob/            Rust: Blob, Buckets and the Carrier trait; the adversary's objects (L2)
  crates/core/            Rust: identity, intro, verify, sessions over OpenMLS, the vault
    src/config.rs         every constant, read as config::part::VALUE
    src/vocab.rs          every closed set as an enum (PeerState, Refuse)
    src/vault.rs          Argon2id + XChaCha20-Poly1305 at rest
  crates/carriers/        Rust: file and stdio carriers; depends on blob and nothing secret
  crates/cli/             Rust: the `unheld` binary; tests/rules.rs checks the crate graph
  crates/relay/           Rust: the relay, one static binary, and the relay carrier (docs/RELAY.md)
  crates/py/              Rust: the core as a Python module over PyO3, with its stub and tests (docs/PYTHON.md)
  transport/              planned: Arti (Tor) embedding, pluggable transports
  mcp/                    planned: the Model Context Protocol server, same binary (`unheld mcp`)
  ffi/ wasm/              planned: UniFFI and WebAssembly bindings (docs/INTEGRATION.md)
  shells/                 later: desktop and mobile shells over core
  tooling/                planned, Python under UV: traffic simulations, doc generation, release tooling
    pyproject.toml
    tests/test_rules.py   the production rules as tests
  tests/                  planned
    adversarial/          malicious relay and malicious contact suites
    fuzz/                 cargo-fuzz targets for every parser of untrusted bytes
  xtask/                  planned, Rust: `cargo xtask repro | release`
```

## Commands

Prerequisite, once per machine (no Rust toolchain was installed when the repository was created):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable --profile minimal
cargo install cargo-deny cargo-vet cargo-fuzz
brew install tamarin-prover/tap/tamarin-prover   # the formal model
```

Rust side (from the repository root):

```bash
cargo build --workspace
cargo test --workspace                      # unit tests, the two-party law tests, and tests/rules.rs
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                            # licences and advisories (install cargo-deny)
cargo vet                                   # crate review status (install cargo-vet)
# planned: cargo test -p adversarial, cargo fuzz run <target>, cargo xtask repro
```

The Python module (from `crates/py`; the Rust toolchain must be on the path):

```bash
uv sync              # builds the module into .venv with maturin
uv run pytest -q     # the laws from Python
```

Running two clients against a local relay (Phase 1 target):

```bash
export UNHELD_HOME=$(mktemp -d) UNHELD_PASSPHRASE=demo     # scripted; omit for prompts
U="cargo run -q --release --"
$U --profile alice id new alice;  $U --profile bob id new bob
$U --profile alice intro export > a.intro;  $U --profile bob intro export > b.intro
$U --profile alice intro import bob b.intro;  $U --profile bob intro import alice a.intro
$U --profile alice verify bob;  $U --profile bob verify alice      # read the digits aloud
echo "hello" | $U --profile alice send bob | $U --profile bob open
```

## Ports

Nothing in the proof of concept opens a listening socket. The planned development relay's port is a value in `config.rs`, and production relays are reached as onion services with no public port.

## Workflow for a change

1. Read AGENTS.md. If the change is near identity, sessions, queues, transport, storage or linked devices, write the design note in `docs/decisions/` first and stop for review.
2. Read the file and its tests. Write the adversarial test before the feature where one applies.
3. Implement in Rust for anything touching a secret, Python under UV for tooling.
4. Run the full command list above. A failing rule check is a bug in the change, not in the check.
5. Red-team the change in the pull request text: the strongest attack and what the tests do about it, and cite the TRACE.md row of every law touched.
6. Stage specific files, commit topically, and wait for the owner's confirmation before pushing.

## Writing

All prose in this repository, including documentation, design notes, user-facing text and comments longer than one line, is written in flowing sentences linked by commas and conjunctions, with no staccato fragments, no parallel triples, no em-dashes, and every acronym written out the first time. User-facing text never uses the words "unhackable", "military grade" or "100% secure", and always names what the system does not protect against alongside what it does.
