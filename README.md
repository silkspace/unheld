# unheld

A messenger where "the server can't read it" is a compile error, not a privacy policy.

```
Carrier = { put : Blob → (), get : () → Blob }     -- names no other type. ever.
Blob    = [u8; B], B ∈ Buckets                      -- fixed sizes. no header. no version byte.
Peer    = built by verify alone                      -- no constructor, no session, no message.
```

![two vaults, one file carrier, every refusal shown live](docs/demo.gif)

That first line is the whole threat model. Correctness is a square that commutes for the two parties; security is the same square failing to commute, totally, for every morphism an adversary can insert. Your relay, your mail provider, the app you pasted into, a court, a mole, and us: everyone downstream of `seal` is a function from `Blob` to `()`. The crate that implements carriers is forbidden by `cargo deny` from importing a key type. Not a promise. A build failure.

## the parts that bite

**No phone number, no directory, no server.** Identity is a keypair you generated. A contact is a fingerprint you compared out loud. Messages are padded blobs you move over anything: clipboard, file, email, iMessage, a USB stick, a mesh radio, or an unheld relay that stores ciphertext and forgets. Two laptops and a clipboard is the MVP.

**Verification is the only constructor.** `send` takes a `Peer`. `Peer` has one constructor and it is `verify(Intro, Fp) → Peer ⊕ Refuse`. There is no `--skip-verify` because there is nothing for it to skip. A changed key is a type state (`Changed`) that `seal` refuses until you compare again.

**Ghost users are a parse error.** Groups are MLS (RFC 9420). A roster change is a `Control` message signed by a `Verified` member with policy rights, opened by every member, shown to every member. The GCHQ "just add a silent participant" proposal is not a policy question here. It does not typecheck.

**Linked devices can't be phished with a QR code.** `enroll : Id × Device × Confirm → Id'`, and `Confirm` is produced on an existing device after it displays the new device's fingerprint. The 2025 campaign against Signal users is a type error.

**Us too.** No verb takes an input we hold at runtime. No account, no remote config, no feature flag, no kill switch, no forced update. The only artefact we control is the binary, so: reproducible builds, independent builders attesting the hash, k-of-n maintainer signatures across jurisdictions, a public transparency log, and `install : Release × Log → () ⊕ Refuse`. If we're compelled, the fork works on day one. iOS is the exception, because Apple re-signs everything, and we say so.

**Agents are correspondents.** `unheld mcp` exposes `message_send` and `messages_read` to a model and deliberately has no `verify`, `enroll`, `rotate`, `split` or `wipe` tool, so a prompt injection cannot perform a ceremony. Your assistant uses your vault under a grant you made, over a carrier that sees ciphertext. The model vendor is just another `Blob → ()`.

## try it

Two profiles on one machine are two vaults, so you can be both ends. Install once, then open two terminals.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh     # if you have no Rust
git clone https://github.com/silkspace/unheld && cd unheld
cargo install --path crates/cli --locked                          # puts `unheld` on your PATH
alias u=unheld
```

```bash
u --profile me  id new me                          # choose a passphrase; keys never leave ~/.unheld/me
u --profile you id new you

u --profile me  intro export --qr > /tmp/me.intro  # a QR on screen, the text in the file
u --profile you intro export --qr > /tmp/you.intro
u --profile me  intro import you /tmp/you.intro
u --profile you intro import me  /tmp/me.intro

u --profile me  verify you --qr                    # terminal one
u --profile you verify me  --qr                    # terminal two: same QR, same 60 digits
                                                   # type `yes` on both only if they match

echo "hello" | u --profile me send you | u --profile you open
```

```
· session started by me
me › hello
```

Then break it. `u --profile me send you -c file:/tmp/blob` writes a 1024-byte blob (type the message, Enter, then Ctrl-D). Paste that file into a note or a chat to yourself: that is everything any carrier ever sees. `u --profile you open -c file:/tmp/blob` reads it, a second open is refused as a replay, and one changed character is refused as malformed. `strings ~/.unheld/me/vault | grep -c hello` prints `0`. Every command needs `--profile`, because the profile is which of you is speaking. `rm -rf ~/.unheld/me ~/.unheld/you` deletes both identities completely, since nothing about them exists anywhere else.

## the laws

24 of them in [KERNEL.md](KERNEL.md), each with who enforces it: the compiler, the crate graph, a Tamarin lemma, a proptest, a Kani harness, or a cited proof we inherit from MLS and don't redo. The five that answer "who holds the key":

| | | |
|---|---|---|
| L2 | zero custody | carriers crate cannot depend on any secret type |
| L3 | no skip | no `Peer` without a matched pairwise fingerprint |
| L14 | key change blocks | `Changed` peer ⇒ `seal` is `Refuse` |
| L15 | enrolment needs a witness | new device confirmed on an old device, fingerprint shown |
| L16 | no ghost | roster change ⇒ signed by a verified member ⇒ shown to all |

[TRACE.md](TRACE.md) maps every law to a phase, a test, a review layer and the screen where you see it. Rows with gaps say so.

## status

Proof of concept. Two profiles exchange introductions, compare a pairwise 60-digit number, and talk through a file or a pipe with Messaging Layer Security underneath and an Argon2id-locked vault at rest. Sending before verification is refused, a welcome from an unverified sender is refused and its group deleted, replay and tampering are refused, and the carriers crate is checked by test to depend on nothing that can name a key.

```
cargo test --workspace            # 10 tests: laws L1, L3, L4, L8, L11 and the crate graph
./scripts/demo.sh                 # two vaults, one file carrier, every refusal shown live
```

<details><summary>what the demo prints</summary>

```
1. two identities, keys generated on device
identity alice created; public prefix 35bb2660c7
identity bob created; public prefix ac50e658a2

2. introductions exchanged out of band (here: files)
bob staged as Pending; run `unheld verify bob`
alice staged as Pending; run `unheld verify alice`

3. sending before verification is refused (L3)
refused: peer is not verified; run `verify` and compare the digits
exit 2

4. the pairwise number is the same on both sides
refused: fingerprint not confirmed
  69747 43550 11305 49452 90848 59417 32898 32037 74821 16992 72427 61762
refused: fingerprint not confirmed
  69747 43550 11305 49452 90848 59417 32898 32037 74821 16992 72427 61762

5. both confirm by voice (here: yes on stdin)
bob is Verified
alice is Verified

6. alice → bob through a file; the file holds a fixed-size blob
blob: 1366 chars of base64url, 1024 raw bytes
[session started by alice]
alice: the carrier is a trait over bytes


7. bob → alice through a pipe
bob: and it cannot read this


8. replay is refused (L11)
refused: message was already opened, or arrived outside the tolerance window
exit 2

9. a flipped byte is refused (L8)
refused: blob is malformed
exit 2

10. peers and the vault at rest
bob              Verified  ac50e658a2  sessions 1  intro consumed
alice            Verified  35bb2660c7  sessions 1  intro unused
vault header: UNHELD01
no plaintext in vault
```

</details>

Not yet: Tamarin model, property tests per law, groups above two, devices, rotation, recovery, reproducible builds, the log. See TRACE.md for which rows are green.

Primitives are never written here. Ratchet: [OpenMLS](https://github.com/openmls/openmls). Tor: [Arti](https://gitlab.torproject.org/tpo/core/arti). Everything else: RustCrypto, pinned, `cargo vet`'d. We hand-roll the architecture and not one byte of crypto. See [`docs/decisions/001`](docs/decisions/001-ratchet-and-licence.md) for why not libsignal (licence, not safety).

## what it does not protect

A device whose kernel belongs to someone else, a correspondent who is careless or hostile, and a person being coerced. Every client says this on first run. If you need a messenger that protects against these, it does not exist, and anyone selling you one is lying.

## break it

Read [KERNEL.md](KERNEL.md), find a law you can violate, open an issue with the attack. The best issue before the first release gets credited in the first release. Disclosure terms are in [docs/MAINTAINERS.md](docs/MAINTAINERS.md); we never pay for silence.

## read

| | |
|---|---|
| [IDEA.md](IDEA.md) | what's actually wrong with Signal, WhatsApp, Telegram; threat tiers T0–T8; architecture; roadmap |
| [KERNEL.md](KERNEL.md) | the signature, the 24 laws, the category, attacks as squares that fail to commute, the language |
| [TRACE.md](TRACE.md) | law → phase → test → review → screen; MVP acceptance; known gaps |
| [OATH.md](OATH.md) | what the humans promise, signed with release keys |
| [docs/MAINTAINERS.md](docs/MAINTAINERS.md) | hardware keys, builders, no agent holds a credential |
| [docs/CLI.md](docs/CLI.md) · [docs/MCP.md](docs/MCP.md) · [docs/INTEGRATION.md](docs/INTEGRATION.md) | the three surfaces |
| [AGENTS.md](AGENTS.md) · [CLAUDE.md](CLAUDE.md) | how to work here |

## licence

AGPL-3.0 for anyone who publishes their source. Commercial licence for anyone who doesn't. The name is a trademark that travels with [OATH.md](OATH.md): a fork that keeps the promises may use it, a release that breaks them may not.
