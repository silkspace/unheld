# TRACE.md: every law, traced to the plan, the tests, the review and the screen

Every law has a phase, a test, a review layer and a screen, and this file is where that is checked. Each law in KERNEL.md appears once below with the inflation phase that delivers it, the test that holds it, the review layer that catches a regression before a release, and the place in the client where a user sees it. A pull request that touches a law cites its row, and a row with a blank is a gap we know about and say so.

## Review layers

| Layer | What it is | When |
|-------|------------|------|
| R1 | Design note in `docs/decisions/` reviewed against the threat model and the laws it touches | before code near a key |
| R2 | Tamarin model with the law as a lemma | before and with the code |
| R3 | Compiler, crate graph and `cargo deny` | every build |
| R4 | Property tests, adversarial carriers, fuzz targets, Kani harnesses | every pull request |
| R5 | Reproduction on independent builders, transparency log, threshold signatures | every release |
| R6 | The red-team paragraph in the pull request and a second human's read | every merge |
| R7 | External audit, published whole | before stable and after any change to a ratchet instance |
| R8 | Public disclosure window and a protocol that forks without us | always |

## The matrix

| Law | Phase | Test | Review | Client surface |
|-----|-------|------|--------|----------------|
| L1 roundtrip | 3 | proptest over sessions and messages | R4 | none needed |
| L2 zero custody | 1 (POC), 2 | `carriers_cannot_depend_on_core`; Tamarin `secrecy` against the carrier; `cargo deny` ban and grep for network calls outside `Carrier` to come | R3, R7 | relay and carrier picker shows "this carrier sees only ciphertext" |
| L3 no skip | 1 (POC) | compiler (one constructor); Tamarin `seal_only_to_a_genuine_key` and `opened_was_sealed` (formal/); `no_impersonation` stated, search open | R2, R3 | the verify screen, which blocks sending until the pairwise number is compared |
| L4 uniform size | 3 | proptest on blob length; Kani harness | R4 | none; attachments show "sent as N chunks" |
| L5 forward secrecy | 3 | cited proof; regression test on key deletion after ratchet step | R7 | none |
| L6 post-compromise | 3 | cited proof; test that a leaked state stops opening after a round trip | R7 | none |
| L7 unlinkability | 3, 5 | statistical test on blob distribution; Tamarin equivalence where tractable | R2, R4, R7 | none |
| L8 fail closed | 3 | proptest that every `Refuse` path allocates no blob and leaves state unchanged | R3, R4 | an error is a sentence that says what was refused and why |
| L9 deniability | 3 | cited proof for n = 2; interface test that group sessions report `deniable = false` | R7 | group header says messages are signed among members |
| L10 erasure | 3 | `forget` deletes a peer's sessions and a late message is refused; `wipe` leaves no file; the duress passphrase wipes and answers as a wrong one (tests) | R4 | `forget`, `duress`, `wipe` |
| L11 replay and reflection | 3 | adversarial carrier that replays and reflects | R4 | none; refused silently and counted |
| L12 detectable omission | 3 | adversarial carrier that drops and reorders | R4 | a gap marker in the thread: "a message between these two was not delivered" |
| L13 bounded state | 3 | flooding carrier; Kani on the skipped-key cap | R4 | none |
| L14 key change blocks | 1 (POC) | compiler on `Changed`; `changed_key_blocks_until_verified_again`; Tamarin `seal_only_to_a_genuine_key` with `changed_then_verified_again` | R2, R3, R4 | contact turns red with "key changed, verify again"; send disabled |
| L15 enrolment needs witness | 1 (POC) | `enroll` takes the human's answer and refuses without it; `a_second_device_needs_a_witness_and_then_reaches_every_session` (no yes, no device; the enrolment opens on the requesting device alone; both devices read and either writes as one person; revocation reaches every session and the revoked device); Tamarin `device_needs_witness` (formal/) | R2, R3 | `devices request` shows sixty digits on the new device, `devices enroll` shows the same digits on the witness and waits for yes |
| L16 no ghost | 1 (POC) | Tamarin `no_ghost` (formal/); `a_roster_change_from_a_non_admin_is_refused_by_every_member` (a client altered to believe it is admin adds a member; every other client refuses the commit and its epoch does not move) | R2, R4, R7 | `open` prints every roster change: who added or removed whom |
| L17 membership secrecy | 1 (POC) | cited MLS proof; `a_group_of_three_and_its_laws` (a newcomer opens nothing sealed before joining, a removed member opens nothing sealed after) | R7 | `group roster` |
| L18 vouch is not verify | 1 (POC) | compiler on `MemberTrust`; `a_group_of_three_and_its_laws` (a member you never verified is `Vouched` with the admin's name, and `group send` lists every reader with their state) | R3 | member badge: Verified, Pending, Changed, or Vouched for by the admin |
| L19 ordered or small | 1 (POC) | `a_large_group_needs_an_ordered_carrier` (one above the bound over an unordered carrier is refused before any key is touched) | R4 | the refusal names the bound and the carriers that do not order |
| L20 explicit entropy | 3 | health-test failure makes `gen` and `seal` refuse | R4 | none; first run reports entropy source |
| L21 shares by ceremony | 5 | compiler; test that `lock` never writes a `Share` | R3, R4 | recovery ceremony screen, interactive, with the shares shown once |
| L22 no creator input | 2 | grep test for network calls outside `Carrier`; no update prompt exists | R3, R6 | about screen: "this version runs forever; updates are offered, never required" |
| L23 release transparency | 4 | test with a forged release and a release missing from the log | R4, R5 | about screen: log entry, builders who reproduced it, how to check it yourself |
| L24 threshold release | 4 | test with k − 1 signatures | R4, R5 | about screen: signers and their jurisdictions |

## Proof of concept, what is green

The workspace under `crates/` delivers criterion 1 in scripted form (intro files, a 60-digit pairwise number that agrees on both sides, send refused until confirmed), criterion 2 with file, stdio and clipboard carriers, tests for L1, L3, L4, L8, L10, L11 and L14, property tests over the blob parser, the crate-graph half of L2 as a test, groups above two with one admin, tests for L16 to L19 and the roster change feed (`docs/decisions/003-groups.md`), and devices of one identity enrolled by a witness, with every peer's roster showing one person however many leaves (`docs/decisions/004-devices.md`). The policy layer is a Tamarin theory in `formal/` with every lemma proved by `scripts/prove.sh`: L2 against the carrier, L3 and L14 as "a seal reaches only a genuine verified key" and "what you open, the named peer sealed to you", and L16 as "a merged roster change was the admin's". Criterion 3 is covered for first contact (a welcome from an unverified sender is refused and its group deleted); the key-change half (L14) has the `Changed` state and no test yet. Criteria 4 and 5 are not started.

## The MVP, as acceptance criteria

The minimum viable product is two people talking with no server, and it is accepted when all of the following are shown live, not described.

1. Two command-line clients on two machines exchange an `Intro` over any channel, compare the pairwise fingerprint by voice, and neither can send before the comparison is recorded (L3).
2. Messages pass as pasted blobs through a third program (a mail client, a chat client, a file), and the laws L1, L4, L8, L10, L11, L12, L13 and L14 are green in the test suite with the adversarial carriers.
3. An attacker in the middle substitutes a public key at introduction and at a later key change, and both attempts leave the sender unable to send (L3, L14).
4. The binary is reproduced on a second machine from the tag and the hashes match (L23, in its two-builder form).
5. The first-run screen names what the system does not protect and the about screen names the log entry.

Phase 4 adds the share-sheet carrier and one mobile shell with the same criteria re-run; Phase 5 adds the ordered relay for large groups, devices and recovery with L15 and L21.

## Known gaps, stated

- **MLS framing is readable by the carrier.** Session identifier, epoch and content type of every message, and the ciphersuite and recipient count of a welcome, are in the clear inside the padding. Accepted for the overlay in `docs/decisions/002-carrier-view.md`, measured by `unheld inspect`, pinned by a test, and reopened with the relay queue design.
- **Groups without a server.** L19 is a refusal, not a solution; large groups need an ordered carrier, and the only ordered carrier planned is the relay queue in Phase 5. Below the bound, two roster changes by the one admin that cross in transit still fork the group, and the fork shows as a refusal on one side with no automatic repair. A consensus among members over an unordered carrier is possible and is not designed.
- **Equal devices.** Every enrolled device holds the identity key, so a stolen enrolled device is the whole identity until another device revokes it, and the thief can race to revoke yours. The ceremony takes four hand-overs because a device cannot introduce itself before it holds its certificate. Whether a primary-device model or a threshold over devices serves better is open; see `docs/decisions/004-devices.md`.
- **One admin per group.** Roster rights are held by the creator alone, so a group outlives its admin only by being started again. Members leave by deleting their own keys and stay in the others' roster until the admin removes them. Self-updates for post-compromise security are accepted from any member and are not yet sent.
- **iOS.** L23 cannot be checked by the user on iOS because Apple re-signs the binary. The about screen says so.
- **Endpoint hygiene.** Keyboard dictionaries, app-switcher snapshots, backup exclusion and clipboard clearing are a checklist in the shells with a test where the platform allows one, which is not everywhere.
- **L7 proof.** Observational equivalence in Tamarin is tractable for small models; the full unlinkability claim will rest partly on a statistical test and an audit.
- **Social recovery.** Shamir shares held by friends reveal who your friends are to anyone who sees the ceremony. Whether a recovery that does not leak the graph exists is open.
- **Voice and video.** Not in any phase yet, and onion-routed calls will state their latency when they come.
