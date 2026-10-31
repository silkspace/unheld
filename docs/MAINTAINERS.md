# Maintainers: hygiene, keys and the machines we work on

The protocol removes us from the trust path, so the remaining way to spoof the system is through us: our laptops, our accounts, our keys and the tools that act on our behalf. This document is the operational half of OATH.md and it is checked at every release by the person who did not build it.

## Identities and keys

Each maintainer has a release key on a hardware token (a YubiKey or equivalent) that never existed on a general-purpose machine, with a second token in a separate place as its backup. The key signs release metadata and this oath and nothing else. Commits are signed with a separate key, also on hardware, so a stolen commit key cannot ship a release. Fingerprints of both are published in this file, in the transparency log, and on at least two channels we do not control, so a compromise of our website or repository cannot rewrite them. Release signing is k of n with n maintainers in at least two jurisdictions and k at least two, held in `config.release`.

Accounts on the forge, the log, the builders and the relay hosts use hardware-token second factors only, no phone numbers, no SMS, no recovery email that routes through a provider who will reset it for a court order.

## Machines

Development happens on a machine that holds no release key and no relay credential, with full-disk encryption, a locked screen, automatic updates, and no third-party keyboards or clipboard managers. The build that counts is never the one on a laptop; it is the reproducible build on the attested builders, and the laptop's job is to produce a commit that reproduces.

Builders are machines run by different maintainers on different infrastructure, each rebuilding every tagged release from source under the pinned toolchain and signing the hash they got. A release ships when enough of them agree. A builder is never also a signer's daily machine.

Relay hosts, where we run any, hold nothing but the relay binary and its config, log nothing, and are treated as already compromised: a stolen relay host gains the attacker the ability to drop blobs and nothing else.

## Agents and assistants

We write code with coding assistants, and an assistant with a shell is a tool that can be turned by a hostile document, a poisoned dependency or a prompt it read in a web page. So the rule is structural rather than hopeful. An assistant may read, propose, edit a working tree and run tests. It never holds a signing key, a release credential, a deploy token, a forge token with merge rights, or any user's data, and the machine it runs on has none of these to find. Every commit it writes is read by a human before merge, and the merge is signed by that human's hardware key. A release built from an unreviewed agent commit is a release we treat as compromised.

## Dependencies

Every crate that touches a key or a plaintext is reviewed under `cargo vet` by a named maintainer before it is used or upgraded, with the review recorded in the repository. `cargo deny` enforces the licence and advisory policy in CI, and the carriers crate is forbidden from depending on the secret crate by a `cargo deny` ban, which is how L2 is kept true. Upgrading a cryptographic dependency is its own commit with its changelog read and summarised, never part of a feature.

## Disclosure

A vulnerability reported to us is acknowledged within `config.disclosure.ack_days`, fixed or publicly described within `config.disclosure.publish_days` whether or not a fix exists, and credited to the reporter unless they decline. We never pay for silence, never sign an agreement that requires it, and never accept a report under one.

## Release checklist, run by the person who did not build it

1. The tag is signed by a maintainer's commit key and every commit since the last release has a reviewer who is not its author.
2. At least `config.release.builders` builders reproduced the binary hash from the source hash and signed their attestation.
3. The release metadata has at least `k` maintainer signatures from at least two jurisdictions.
4. The release, the attestations and the config hash are in the transparency log and the client's `install` accepts it.
5. The changelog names anything that weakened.
6. `cargo vet`, `cargo deny`, the adversarial suite, the fuzz corpus and the rule checks are green on the builders, not only on a laptop.
