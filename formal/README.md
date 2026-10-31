# The policy layer, proved

`unheld.spthy` is a [Tamarin](https://tamarin-prover.com) theory of everything unheld adds on top of Messaging Layer Security: the self-signed introduction handed over the carrier, the Pending, Verified and Changed states, the fingerprint ceremony over a channel the carrier never touches, the verified-sender rule at join, and the single-admin rule for roster changes. MLS itself has published proofs and is one symmetric session key here. The adversary is the carrier with full Dolev-Yao power over every blob, plus a `Reveal` rule that hands it a long-term key and stands for the one thing the README says is not protected, a device someone else controls. Sessions, parties and keys are unbounded.

```bash
brew install tamarin-prover/tap/tamarin-prover     # or see tamarin-prover.com for other systems
./scripts/prove.sh                                 # proves every lemma, fails on any that is not
```

One prover at a time: a run takes several gigabytes, and the proofs here were found on a laptop with the search for `no_impersonation` still open when the budget ran out.

## What is proved

| Lemma | Law | Statement |
|-------|-----|-----------|
| `seal_only_to_a_genuine_key` | L3, L14 | Whatever the carrier injects, a message is sealed only to a key the named peer generated and the sender verified. Holds with no assumption at all, even against a revealed key, because the ceremony's channel is not the carrier. |
| `opened_was_sealed` | L3 | If B opens a message as from A, A sealed that message, unless A's device is someone else's. |
| `no_impersonation` | L3 | The sharper form: A sealed it to B. Stated, with the lemma above as a reusable step; its proof search runs past the twenty-minute budget this was written under and is the one open item in this file. |
| `secrecy` | L2 | A sealed message never reaches the carrier's knowledge while both devices are their owners'. |
| `no_ghost` | L16 | A roster change any member merges was committed by the group's admin, unless some device is someone else's. The carrier alone produces none. |
| `join_means_started`, `start_key_secret` | | The two steps the prover reuses: a joined session with an honest sender was started by that sender for you and its key is secret whatever your own device did, and a started session's key is secret whenever the recipient is honest. |
| `executable`, `group_executable`, `changed_then_verified_again` | | The honest runs exist, including a key change followed by a fresh ceremony and a session under the new key. The laws are not vacuous. |

## What the prover found on the way

The first draft bound a welcome to the recipient's encryption key alone. Tamarin produced an unknown-key-share trace: a hostile third party presents your peer's encryption key inside its own signed key package, your welcome meant for the third party lands on your peer, and your peer reads words you addressed to someone else. The second draft named the recipient's identity key in the welcome, and the prover produced the mirror image: a hostile verified peer re-signs a welcome it cannot read, and you join a session with the wrong party. The theory now names the recipient outside the encryption and the sender inside it, which is what MLS does by construction with the key package hash and the confirmation tag, and the point of writing the model was to find out that those two bindings are load-bearing rather than to assume it. Both traces are in the history of this file.

## What is not modelled

Forward secrecy, post-compromise security and membership secrecy (L5, L6, L17) are MLS properties with their own proofs and are cited, not redone. The Changed state blocks sealing in the code by a match on `PeerState` and is tested there; here Changed is an observation, and the lemma that matters is that no sequence of injected introductions makes a seal reach an unverified key. Enrolment (L15) and recovery (L21) join the theory when those verbs exist. Unlinkability (L7) is an equivalence property and is measured by `unheld inspect` and a pinned test rather than proved.
