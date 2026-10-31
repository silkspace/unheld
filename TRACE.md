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
| L2 zero custody | 2 | `cargo deny` ban on `carriers → secret`; grep for network calls outside `Carrier` | R3, R7 | relay and carrier picker shows "this carrier sees only ciphertext" |
| L3 no skip | 2, 3 | compiler (one constructor); Tamarin authentication lemma | R2, R3 | the verify screen, which blocks sending until the pairwise number is compared |
| L4 uniform size | 3 | proptest on blob length; Kani harness | R4 | none; attachments show "sent as N chunks" |
| L5 forward secrecy | 3 | cited proof; regression test on key deletion after ratchet step | R7 | none |
| L6 post-compromise | 3 | cited proof; test that a leaked state stops opening after a round trip | R7 | none |
| L7 unlinkability | 3, 5 | statistical test on blob distribution; Tamarin equivalence where tractable | R2, R4, R7 | none |
| L8 fail closed | 3 | proptest that every `Refuse` path allocates no blob and leaves state unchanged | R3, R4 | an error is a sentence that says what was refused and why |
| L9 deniability | 3 | cited proof for n = 2; interface test that group sessions report `deniable = false` | R7 | group header says messages are signed among members |
| L10 erasure | 3 | zeroise-on-drop types; memory read after `forget` and after `wipe` | R4 | expiry setting per contact; duress setup screen |
| L11 replay and reflection | 3 | adversarial carrier that replays and reflects | R4 | none; refused silently and counted |
| L12 detectable omission | 3 | adversarial carrier that drops and reorders | R4 | a gap marker in the thread: "a message between these two was not delivered" |
| L13 bounded state | 3 | flooding carrier; Kani on the skipped-key cap | R4 | none |
| L14 key change blocks | 3 | compiler on `Changed`; Tamarin; test that `seal` refuses | R2, R3, R4 | contact turns red with "key changed, verify again"; send disabled |
| L15 enrolment needs witness | 5 | compiler on `Confirm`; Tamarin | R2, R3 | devices list; new device shows its fingerprint on an existing device and waits |
| L16 no ghost | 5 | Tamarin on the policy layer; test that an unsigned or unauthorised commit is refused | R2, R4, R7 | roster view with a change feed every member sees: who added whom, when |
| L17 membership secrecy | 5 | cited MLS proof; test that a removed member cannot open the next epoch | R7 | roster view |
| L18 vouch is not verify | 5 | compiler on `state`; interface test | R3 | member badge: Verified, Changed, or "vouched for by Alice" |
| L19 ordered or small | 5 | test that `start` refuses a large roster over an unordered carrier | R4 | group creation says which carriers can hold a group this size |
| L20 explicit entropy | 3 | health-test failure makes `gen` and `seal` refuse | R4 | none; first run reports entropy source |
| L21 shares by ceremony | 5 | compiler; test that `lock` never writes a `Share` | R3, R4 | recovery ceremony screen, interactive, with the shares shown once |
| L22 no creator input | 2 | grep test for network calls outside `Carrier`; no update prompt exists | R3, R6 | about screen: "this version runs forever; updates are offered, never required" |
| L23 release transparency | 4 | test with a forged release and a release missing from the log | R4, R5 | about screen: log entry, builders who reproduced it, how to check it yourself |
| L24 threshold release | 4 | test with k − 1 signatures | R4, R5 | about screen: signers and their jurisdictions |

## Proof of concept, what is green

The workspace under `crates/` delivers criterion 1 in scripted form (intro files, a 60-digit pairwise number that agrees on both sides, send refused until confirmed), criterion 2 with file and stdio carriers and tests for L1, L3, L4, L8 and L11, and the crate-graph half of L2 as a test. Criterion 3 is covered for first contact (a welcome from an unverified sender is refused and its group deleted); the key-change half (L14) has the `Changed` state and no test yet. Criteria 4 and 5 are not started.

## The MVP, as acceptance criteria

The minimum viable product is two people talking with no server, and it is accepted when all of the following are shown live, not described.

1. Two command-line clients on two machines exchange an `Intro` over any channel, compare the pairwise fingerprint by voice, and neither can send before the comparison is recorded (L3).
2. Messages pass as pasted blobs through a third program (a mail client, a chat client, a file), and the laws L1, L4, L8, L10, L11, L12, L13 and L14 are green in the test suite with the adversarial carriers.
3. An attacker in the middle substitutes a public key at introduction and at a later key change, and both attempts leave the sender unable to send (L3, L14).
4. The binary is reproduced on a second machine from the tag and the hashes match (L23, in its two-builder form).
5. The first-run screen names what the system does not protect and the about screen names the log entry.

Phase 4 adds the share-sheet carrier and one mobile shell with the same criteria re-run; Phase 5 adds groups, devices and recovery with L15 to L19 and L21.

## Known gaps, stated

- **Groups without a server.** L19 is a refusal, not a solution; large groups need an ordered carrier, and the only ordered carrier planned is the relay queue in Phase 5. A consensus among members over an unordered carrier is possible and is not designed.
- **iOS.** L23 cannot be checked by the user on iOS because Apple re-signs the binary. The about screen says so.
- **Endpoint hygiene.** Keyboard dictionaries, app-switcher snapshots, backup exclusion and clipboard clearing are a checklist in the shells with a test where the platform allows one, which is not everywhere.
- **L7 proof.** Observational equivalence in Tamarin is tractable for small models; the full unlinkability claim will rest partly on a statistical test and an audit.
- **Social recovery.** Shamir shares held by friends reveal who your friends are to anyone who sees the ceremony. Whether a recovery that does not leak the graph exists is open.
- **Voice and video.** Not in any phase yet, and onion-routed calls will state their latency when they come.
