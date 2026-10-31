# KERNEL.md: the whole system in one signature

This is the smallest statement of unheld that is still the whole thing. Everything in IDEA.md is an inflation of what is on this page, and every typed interface, test and proof must be traceable to one line here. If a feature cannot be written as an instance of these types or a consequence of these laws, it does not belong.

## The signature

```
-- Values. Only Blob and Intro ever leave the device, and Share leaves only by ceremony.

Rng      = abstract                                  -- explicit, health-tested entropy
Id       = { sk_sign, sk_kem, pub : Pub, devices : [Device] }
Pub      = { pk_sign, pk_kem }
Device   = Sign(sk_sign, { pk_dev, name, enrolled_at })   -- one Id, several devices
Fp       = H(Pub_a ++ Pub_b)                         -- pairwise safety number, ≥ 128 bits
Intro    = Sign(sk_sign, Pub ++ devices ++ prekeys ++ version)
Peer     = { pub : Pub, name, state : Verified | Changed }   -- built by verify alone
Vouch    = Sign(sk_sign_a, Pub_c)                    -- Alice says Carol is Carol; never a Peer
Ratchet  = abstract                                  -- Signal (n = 2), MLS (n ≥ 2)
Roster   = { members : [Peer ⊕ Vouch], epoch, policy }
Session  = Ratchet state over one Id and one Roster, as a sequence of epochs
Msg      = { kind : Data | Control, seq, prev_hash, body, ttl }
Blob     = [u8; B]  where  B ∈ Buckets               -- no cleartext header, no version byte
Carrier  = { put : Blob → (), get : () → Blob, ordered : Bool }   -- names no other type
Vault    = Enc(k_dev, { Id, [Peer], [Session] })     -- k_dev from enclave or Argon2id
Share    = one of n Shamir shares of Id              -- a secret; exists only during split
Release  = Sign_{k of n}({ h_source, h_binary, h_config, version })   -- no single signer
Log      = append-only, publicly auditable list of Release and builder attestations

-- Verbs. Each is total and fails closed.

gen     : Rng                       → Id
intro   : Id                        → Intro
verify  : Intro × Fp                → Peer ⊕ Refuse
vouch   : Id × Peer                 → Vouch
rotate  : Id × Rng                  → Id' × Sign(sk_old, Pub')          -- continuity statement
enroll  : Id × Device × Confirm     → Id'            -- Confirm comes from an existing Device
start   : Id × Roster × Carrier     → Session ⊕ Refuse   -- Refuse if |roster| > small and ¬ordered
add     : Session × Peer            → Session'       -- a Control Msg every member opens
remove  : Session × Peer            → Session'
seal    : Session × Msg × Rng       → Session' × Blob
open    : Session × Blob            → Session' × Msg ⊕ Refuse
forget  : Session × (Time, Count)   → Session'
lock    : k_dev × State             → Vault          (unlock is its inverse, and the only one)
split   : Id × (k, n) × Ceremony    → [Share]        (join is its inverse, on a new device)
wipe    : Duress                    → ()
install : Release × Log             → () ⊕ Refuse  -- the only verb whose input the creator makes
```

A conversation is `start`, then alternating `seal` and `open` with the `Blob` moved by any `Carrier`, with `forget` on a clock and a counter. A group is the same verbs with the MLS instance of `Ratchet`, and `add` and `remove` are `Control` messages that every member must `open`. A mesh node, a relay queue, a clipboard and an email account are all `Carrier` and none of them contains a ratchet.

## The laws

Each law is a theorem on the model, a property test on the code, or a fact the compiler or the crate graph enforces, and the inflation says which.

| # | Law | Statement | Enforced by |
|---|-----|-----------|-------------|
| L1 | Roundtrip | `open(s', seal(s, m).blob) = m` whenever `s` and `s'` are two ends of one session | property test |
| L2 | Zero custody | The carriers crate cannot depend on any crate that defines a secret type, and `Carrier` names only `Blob`, so nothing a carrier or operator holds can produce a plaintext | crate dependency graph; `cargo deny` bans the edge |
| L3 | No skip | `Peer` has one constructor and it is `verify`, so no `Session` contains a party whose pairwise `Fp` was not matched | type system; Tamarin authentication lemma |
| L4 | Uniform size | `|seal(s, m).blob| ∈ Buckets`, `Refuse` produces no bytes, and a chunked attachment pads its final chunk | property test |
| L5 | Forward secrecy | Compromise of `s_n` opens no blob sealed from `s_i`, `i < n` | inherited from the ratchet; cited proof |
| L6 | Post-compromise security | After one honest round trip following compromise, the adversary opens no further blob | inherited; cited |
| L7 | Unlinkability | A carrier cannot tell two blobs from one session from two blobs from different sessions; a receiver trial-decrypts rather than reading a header | property test on blob distribution; Tamarin equivalence where tractable, statistical test where not |
| L8 | Fail closed | Every verb is total; on mismatch it returns `Refuse` with its input state unchanged, and there is no flag or environment variable that weakens a check | type system; property test that `Refuse` paths allocate no blob |
| L9 | Deniability | For a two-party transcript the receiver can forge an identically distributed one; group messages are signed per sender and this law does not hold for them, which the interface says | inherited for n = 2; cited |
| L10 | Erasure | After `forget` no key for older blobs exists in `s` or any `Vault` from it; after `wipe` no key exists at all | zeroise-on-drop; test that reads memory after forget; `wipe` test |
| L11 | Replay and reflection | A blob opened once, or a blob the session itself sealed, returns `Refuse` on `open` | property test |
| L12 | Detectable omission | `seq` and `prev_hash` in every `Msg` let a receiver detect a dropped or reordered message and show it | property test with a dropping carrier |
| L13 | Bounded state | Skipped-key storage and trial-decryption candidates are capped by config and an over-cap blob is refused, so a flood cannot exhaust memory | property test with a flooding carrier |
| L14 | Key change blocks | A `Pub` differing from the stored `Peer` sets `state = Changed`; `seal` to a `Changed` peer is `Refuse` until `verify` runs again; a continuity statement shortens the ceremony and never replaces it | type system; Tamarin |
| L15 | Enrolment needs a witness | `enroll` requires a `Confirm` signed by an existing `Device` of the same `Id`, produced after that device displayed the new device's fingerprint | type system; Tamarin |
| L16 | No ghost | Every `Roster` change is a `Control` message signed by a `Verified` member with policy rights, and every member's client shows it; no carrier, relay or operator can produce one | inherited from MLS; Tamarin on our policy layer |
| L17 | Membership secrecy | A removed member opens no blob sealed after its removal epoch, and an added member opens no blob sealed before its join epoch | inherited from MLS; cited |
| L18 | Vouch is not verify | A `Vouch` renders as "Alice vouches for Carol" and never changes `state` to `Verified`; the interface shows the verification state of every member, every time | type system |
| L19 | Ordered or small | `start` refuses a roster larger than `config.small_group` over a carrier with `ordered = false`; small groups use pairwise fan-out, large groups require ordering | type system; test |
| L20 | Explicit entropy | `gen` and `seal` take an `Rng` that mixes hardware and OS sources and fails closed on health-test failure; no verb reaches for ambient randomness | type system; health test |
| L21 | Shares by ceremony | `Share` is produced only by `split`, which requires an interactive ceremony, is never written by `lock`, and is zeroised when the ceremony ends | type system; test |
| L22 | No creator input at runtime | No verb other than `install` has an input the creator can supply after the binary ships: no account, directory, remote config, feature flag, kill switch or forced update exists, and the client runs indefinitely on the version it has | signature; grep test for network calls outside `Carrier` |
| L23 | Release transparency | `install` refuses a `Release` not present in `Log` with attestations from at least `config.release.builders` independent builders who reproduced `h_binary` from `h_source` | type system; test with a forged release |
| L24 | Threshold release | A `Release` is valid only with `k` of `n` maintainer signatures from keys held by people in different jurisdictions, so no one maintainer, compelled or compromised, can ship | type system; test with `k - 1` signatures |

L22, L23 and L24 answer the creator as adversary: the only artefact the maintainers control is the binary, and a user checks it without trusting them, except on iOS, where Apple re-signs every binary and the limit is stated. L2, L3, L14, L15 and L16 are the five that answer the question this project exists for, in its two-party and its group forms. L2 is why a court order or a mole gets nothing. L3 and L14 are why substitution at introduction or at key change fails. L15 is why the 2025 linked-device phishing fails. L16 is why the ghost-user proposal, the group form of legal compulsion, fails.

## The category

Objects are the types of the signature and morphisms are the verbs with their composites. Write **U** for this category. Write **C** for the adversary's category: its objects are `Blob`, `()`, `Bool` and finite products of them, and its morphisms are every computable function between those objects, because an adversary holding a carrier may do anything at all to bytes. The inclusion `ι : C → U` is how the adversary acts on the system, and every law below is a statement about which squares commute in **U** and which fail to commute, totally, once a morphism from **C** is inserted.

**Custody is a factorisation.** Every arrow `Blob → Msg` in **U** factors through `Session`, and the arrows into `Session` are `start` and the ratchet endomorphisms, whose sources are `Id`, `Roster` and `Rng`, none of which is an object of **C**. So `Hom_C(Blob, Msg)` is empty, and L2 is the statement that this emptiness is preserved by the crate graph: the carriers crate cannot name an object outside **C**.

**Correctness is a commuting square and security is its failure.**

```
            seal                 c ∈ Hom_C(Blob, Blob)
   Msg ─────────────▶ Blob ─────────────────────────▶ Blob
    │                                                   │
 id │                                                   │ open
    ▼                                                   ▼
   Msg ◀──────────────────────────────────────────── Msg ⊕ Refuse
```

The square commutes with `open ∘ c ∘ seal = id_Msg` exactly when `c = id_Blob` (L1). For every other `c` the composite is `Refuse` (L8, L11), with no partial object in between. The parties' square commutes and the adversary's does not, and the gap between the two is the whole security claim.

**Verification generates the hom-set.** Every arrow into `Peer` is `verify ∘ f` for some `f` into `Intro × Fp` (L3). The adversary's substitution `σ : Pub → Pub'` lifts to a morphism on `Intro`, and the square

```
   Intro × Fp ──verify──▶ Peer ⊕ Refuse
       │                       ║
  σ×id │                       ║  must not commute
       ▼                       ║
   Intro' × Fp ──verify──▶ Refuse
```

fails to commute because `Fp` is computed over both public keys through a channel that is not an object of **C**. The same square with `Peer` replaced by the `Changed` state is L14, and with `Device` and `Confirm` in place of `Intro` and `Fp` is L15.

**The ratchet is a one-way monoid.** The ratchet steps are endomorphisms `r_i : Session → Session` and the monoid they generate has no non-identity units: no `r_i` has a left inverse in **U** (L5), and after one step whose randomness the adversary did not see, no composite of adversary-known arrows reaches the current object (L6). `forget` is a retraction onto a quotient of `Session` from which the earlier objects have no preimage (L10).

**The carrier functor forgets everything but the bucket.** `F : U → C` sends `seal(s, m)` to its blob. L4 says `F` lands in `⊔_{B ∈ Buckets} [u8; B]`, and L7 says `F` is constant on morphisms up to bucket: for the adversary, `F(seal(s, m))` and `F(seal(s', m'))` are indistinguishable whenever the buckets agree. Transcript order is a faithful functor from the free monoid on `Msg` to sequences of `Blob` (L12), so a permutation or deletion in **C** is detected by the failure of faithfulness, and the detection is a morphism to a marked gap rather than a silent identity.

**Group operations do not commute, so order must be total.** Roster changes are morphisms `epoch_n → epoch_{n+1}`, and `add ∘ remove ≠ remove ∘ add` in general. Messaging Layer Security resolves this with a total order on commits, and a carrier with `ordered = false` cannot supply one, so `start` is `Refuse` above the small-group bound (L19). `Hom(epoch_n, epoch_{n+1})` is generated by commits carrying a signature from a `Verified` member with policy rights (L16), which no morphism of **C** can produce, and a removed member's `Session` has no arrow into any later epoch (L17).

**The creator's category has one functor into the system.** The maintainers' objects are `Release` and `Log`, and the only morphism from them into **U** is `install` (L22). Its domain is checked against reproduction by independent builders and a threshold of signatures (L23, L24), so the functor is faithful on exactly the releases that everyone can see.

Every design note in `docs/decisions/` draws its square, names the morphism the adversary adds, and states which composite becomes `Refuse`. A change whose square commutes for the adversary is refused in review regardless of what else it does.

## Attacks as squares that fail to commute

Each attack is a morphism the adversary inserts; each closure is the law under which the resulting composite is `Refuse`.

| Attack | Morphism inserted | Closure |
|--------|-------------------|---------|
| Concurrent roster changes fork a group over an unordered carrier, and a removed member survives in one branch | two non-commuting commits with no total order | `Carrier.ordered`, L19 |
| An operator adds a silent listener to a group | an unsigned commit from **C** | `Roster`, `Control`, L16 |
| Trust in a large group leaks through members nobody verified | `Vouch` treated as `Peer` | `Vouch` as a distinct object, L18 |
| Impersonation through a dismissed key-change warning | `σ : Pub → Pub'` after first contact | the `Changed` state, L14 |
| A phished linked device | `enroll` without a witness | `Confirm` from an existing `Device`, L15 |
| Recovery shares as a key-exfiltration path | `Share` written by `lock` | `split` by ceremony only, L21 |
| Replay, reflection, selective drop | duplication, reversal and deletion in **C** | `seq`, `prev_hash`, L11, L12 |
| Memory exhaustion by a counter jump | an unbounded skip in **C** | the skipped-key cap, L13 |
| Non-repudiation within a group mistaken for two-party deniability | signed sender keys | L9 stated for `n = 2` only |
| Weak entropy on a constrained device | ambient randomness | `Rng` as an explicit argument, L20 |
| A carrier implementation that captures a `Session` | a closure crossing the crate boundary | the crate graph, L2 |
| A compelled or compromised maintainer | a release outside `Log` or below threshold | `install`, L22, L23, L24 |
| Forensic residue around the vault: predictive keyboards, app-switcher snapshots, platform backups, synced clipboards | plaintext leaving through the shell | the endpoint checklist in IDEA.md, tested where the platform allows |
| Expiry defeated by a clock set back | time as the only bound | `forget` on time and count, L10 |
| Second-preimage games on a short per-key fingerprint | a colliding `Pub'` | pairwise `Fp` over both keys at full strength |
| Two people on one phone | one `Vault` | one `Vault` per profile |

A mesh node is a carrier and never an endpoint, so it compiles with no ratchet and no standard library, and the universality claim in the next section is made for carriers and not for endpoints, which need `std`. The licence of the ratchet is a recorded decision, `docs/decisions/001`.

## The language

The kernel is written in Rust, and the reasons are the criteria named in the question.

**Security.** The vetted ratchets are Rust (libsignal, OpenMLS), the embedded Tor is Rust (Arti), and memory safety with `forbid(unsafe_code)` closes the class of bug that has produced most real messenger exploits. Secret types zeroise on drop and the type system carries L2, L3, L8, L14, L15, L18, L20 and L21 at compile time.

**Speed.** Zero-cost abstraction and no garbage collector, so padding, ratchet and storage run at the speed of the primitives and nothing pauses with a key in memory.

**Universality.** A carrier is a trait over a byte array, so a mesh node compiles `no_std` to a microcontroller with no crypto at all, a relay is one static binary, and the endpoint core links into Swift, Kotlin or WebAssembly from one crate with a dependency tree `cargo vet` and `cargo deny` hold to a dozen audited crates. Endpoints need `std` because libsignal does, and that is where the ratchet lives.

**Proofs.** The ratchet proofs exist in Tamarin and ProVerif for Signal and MLS and we cite them (L5, L6, L9, L17). What is ours to prove is the composition: introduction and key change (L3, L14), enrolment (L15), the policy layer over MLS (L16) and the carrier boundary (L2), which is a small Tamarin model plus a crate graph. Bounded model checking with Kani and property tests with proptest cover L1, L4, L7, L8, L10 to L13 and L19 to L21. Cryspen's hax can lift the glue to F* later if a machine-checked link between model and code is wanted.

The alternatives were weighed and lost. C is universal and fast and every bug is a memory bug. Go has a good standard crypto library but a garbage collector, large binaries and no path to a mesh node. Zig is promising and has no vetted ratchet. OCaml and Haskell have the best proof story and the worst universality. Python runs none of the kernel and all of the tooling, under UV.

## Inflation order

1. **Model.** The signature as a Tamarin theory with L2, L3, L14, L15 and L16 as lemmas, proven before any Rust exists.
2. **Types.** The signature as a Rust workspace of types only, no bodies: a `secret` crate for `Id`, `Device`, `Session`, `Share`; a `wire` crate for `Blob`, `Intro`; a `carriers` crate forbidden from depending on `secret`. `Peer` with its one private constructor and its `state`, `Session` generic over a `Ratchet` trait, `Blob` as a const-generic array over the bucket set, every field described. The compiler and `cargo deny` passing on L2, L3, L8, L14, L15, L18, L20 and L21 is the first green test.
3. **Verbs.** Bodies over the libsignal instance, a proptest per law that says property test, Kani harnesses for L4, L8 and L13, and adversarial carriers that replay, reflect, drop, reorder and flood.
4. **Carriers.** Clipboard, share sheet and file, with the endpoint hygiene checklist as tests where the platform allows. Two people can talk and there is no operator to compel.
5. **Instances.** The MLS instance of `Ratchet` with the policy layer, an ordered `Carrier` (the relay queue), `enroll` and `split`, each with the whole table of laws re-run unchanged, because the laws are stated over the signature and not over the instance.
