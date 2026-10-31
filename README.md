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

Three or more is a group. Make a third profile, have it exchange introductions and verify with `me` only, and then:

```bash
u --profile me group new team you them -c file:/tmp/w    # one welcome for both
u --profile you  open -c file:/tmp/w
u --profile them open -c file:/tmp/w
u --profile you  group list                              # me Verified, admin · them Vouched, by me
echo "hello both" | u --profile me group send team -c file:/tmp/g
u --profile you  open -c file:/tmp/g
```

```
· me welcomed you to a group of 3; 1 of them you never verified
g-bd68bc2320 epoch 1  admin me
  Verified me
  Verified you              you
  Vouched  ?7f14c9c118      vouched for by me; you never compared digits with them
[g-bd68bc2320] me › hello both
```

`you` never met `them`, and the client says so every time, including before every `group send`. `group add team more -c file:/tmp/c -w file:/tmp/wm` writes a commit for the members and a welcome for the newcomer; `group remove team them -c file:/tmp/r` writes a commit everyone opens as a line saying who removed whom, after which `them` opens nothing further. Only the one who started the group changes its roster, and every other client refuses a roster change from anyone else before merging it. Above eight people the file, clipboard and pipe carriers are refused, because they cannot order commits, which is the whole reason large groups usually need a server.

A second device is a second profile here. On it, `devices request` makes a vault and prints a request and sixty digits; on the first, `devices enroll phone <request>` prints the digits the request's key makes and asks whether the new device shows exactly them:

```bash
u --profile phone devices request > /tmp/req                   # on the new device
u --profile me    devices enroll phone /tmp/req > /tmp/enrol    # on a device that is you: compare, then `yes`
u --profile phone devices join /tmp/enrol > /tmp/attach         # the phone becomes you
u --profile me    devices connect /tmp/attach -c dir:/tmp/out   # one commit per session, one blob for the phone
u --profile you   open -c file:/tmp/out/you.blob
u --profile phone open -c file:/tmp/out/device.blob
```

```
this device shows (the device that enrols you must show the same digits)

  39817 93856 79539 54586 05372 88161 76648 31771 82941 50534 74928 89249

the new device must show exactly phone

  39817 93856 79539 54586 05372 88161 76648 31771 82941 50534 74928 89249

· me added 1 device
· phone is now a device of this identity
· your session with you now reaches phone
```

From here `you` reads one person with two devices, both open what `you` sends, and what the phone sends arrives as `me ›`. `u --profile me devices revoke phone -c dir:/tmp/rev` writes one commit per session, `you` opens it as `me removed 1 device`, and the phone opens its copy as `another device of yours revoked this one; those keys are deleted` and nothing after. A request that the witness cannot match to a screen is the 2025 linked-device attack, and it is what the default `no` is for.

Then break it. `u --profile me send you -c file:/tmp/blob` writes a 1024-byte blob (type the message, Enter, then Ctrl-D), and `-c clipboard` puts it on the clipboard so you can paste it into any chat and `open -c clipboard` on the other side. Paste the file into a note or a chat to yourself: that is everything any carrier ever sees, and `u inspect -c file:/tmp/blob` shows exactly what. `u --profile you open -c file:/tmp/blob` reads it, a second open is refused as a replay, and one changed character is refused as malformed. `strings ~/.unheld/me/vault | grep -c hello` prints `0`, and the file has no header or magic bytes at all, so nothing identifies it as a vault. Every command needs `--profile`, because the profile is which of you is speaking. `rm -rf ~/.unheld/me ~/.unheld/you` deletes both identities completely, since nothing about them exists anywhere else.

## the laws

24 of them in [KERNEL.md](KERNEL.md), each with who enforces it: the compiler, the crate graph, a Tamarin lemma, a proptest, a Kani harness, or a cited proof we inherit from MLS and don't redo. The five that answer "who holds the key":

| | | |
|---|---|---|
| L2 | zero custody | carriers crate cannot depend on any secret type |
| L3 | no skip | no `Peer` without a matched pairwise fingerprint |
| L14 | key change blocks | `Changed` peer ⇒ `seal` is `Refuse` |
| L15 | enrolment needs a witness | new device confirmed on an old device, fingerprint shown |
| L16 | no ghost | roster change ⇒ signed by a verified member ⇒ shown to all; a device change is not one |

[TRACE.md](TRACE.md) maps every law to a phase, a test, a review layer and the screen where you see it. Rows with gaps say so.

## proved

`formal/unheld.spthy` is the policy layer as a Tamarin theory, with the carrier as a Dolev-Yao adversary over unbounded sessions, parties and keys, and `./scripts/prove.sh` runs the proofs:

| | |
|---|---|
| `seal_only_to_a_genuine_key` | whatever the carrier injects, a seal reaches only a key the named peer generated and you verified (L3, L14), with no honesty assumption at all |
| `opened_was_sealed` | what you open as from A, A sealed, unless A's device is someone else's; the sharper `no_impersonation`, that A sealed it to you, is stated and its search is still open |
| `secrecy` | a sealed message never enters the carrier's knowledge while both devices are their owners' |
| `no_ghost` | a merged roster change was committed by the admin; the carrier alone produces none (L16) |

The prover earned its keep before anything was proved: two drafts of the welcome each admitted an unknown-key-share trace, and the bindings that close them are exactly the two MLS has by construction. [formal/README.md](formal/README.md) has the traces and what is left out.

## status

Proof of concept. Profiles exchange introductions, compare a pairwise 60-digit number, and talk one to one or in groups through a file, a pipe or the clipboard with Messaging Layer Security underneath and an Argon2id-locked vault at rest, and a second device joins an identity only after a device that already is one has seen its digits. Sending before verification is refused, a welcome from an unverified sender is refused and its group deleted, replay and tampering are refused, a roster change from anyone but the admin is refused, and the carriers crate is checked by test to depend on nothing that can name a key.

```
cargo test --workspace            # 24 tests: laws L1, L3, L4, L8, L10, L11, L14 to L19 and the crate graph
./scripts/prove.sh                # Tamarin: every lemma in formal/unheld.spthy
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

Not yet: property tests per law, the ordered relay for large groups, rotation, recovery, reproducible builds, the log. See TRACE.md for which rows are green.

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
| [formal/](formal/README.md) | the policy layer as a Tamarin theory: lemmas, the traces the prover found, what is left out |
| [OATH.md](OATH.md) | what the humans promise, signed with release keys |
| [docs/MAINTAINERS.md](docs/MAINTAINERS.md) | hardware keys, builders, no agent holds a credential |
| [docs/CLI.md](docs/CLI.md) · [docs/MCP.md](docs/MCP.md) · [docs/INTEGRATION.md](docs/INTEGRATION.md) | the three surfaces |
| [AGENTS.md](AGENTS.md) · [CLAUDE.md](CLAUDE.md) | how to work here |

## licence

AGPL-3.0 for anyone who publishes their source. Commercial licence for anyone who doesn't. The name is a trademark that travels with [OATH.md](OATH.md): a fork that keeps the promises may use it, a release that breaks them may not.
