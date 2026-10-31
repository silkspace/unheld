# 001: one ratchet, a permissive dependency tree, and a dual licence

**Status.** Proposed, awaiting a second maintainer.

**Laws touched.** L5, L6, L9, L17 (inherited from the ratchet instance); L2 (crate graph); the universality claim in KERNEL.md.

## The question

KERNEL.md left `Ratchet` with two instances, libsignal for two parties and OpenMLS for groups. libsignal is licensed under the GNU Affero General Public License v3, which makes any client linking it AGPL, which in turn makes distribution through Apple's App Store a grey area we cannot resolve as Signal does by owning the copyright, and makes a commercial licence for embedding impossible, because we cannot relicense someone else's copyleft code. The integration story in `docs/INTEGRATION.md` needs a core that a company can put in a closed app and pay for.

## The decision

Use OpenMLS, which is MIT licensed, as the only `Ratchet` instance, for two parties as well as groups. Keep every dependency that touches a key or a plaintext under MIT, Apache 2.0, BSD or equivalent, enforced by `cargo deny`. Hold the copyright on our own code with a contributor licence agreement so that we can offer the core under two licences: AGPL v3 for anyone who publishes their source, and a paid commercial licence for anyone who does not.

## What it costs

- **Two-party deniability (L9) is gone.** MLS messages are signed by the sender's leaf key so members cannot forge each other, and at two members that means a transcript is non-repudiable in a way a Signal transcript is not. L9 becomes "not provided" rather than "for n = 2 only", and the interface says so.
- **Sealed Sender is gone.** We never used it, because there is no server to hide a sender from in the overlay, and the relay design hides the sender by the queue model instead (L7).
- **Post-quantum status must be checked at implementation time.** The hybrid post-quantum MLS ciphersuites are Internet drafts and OpenMLS tracks them; the decision note is reopened if a hybrid suite is not available when Phase 3 begins.
- **A contributor licence agreement is friction** and some contributors refuse them on principle. We use a short agreement that grants us the right to dual license and promises in return that the AGPL version is always complete, which is the Element and Qt model and is compatible with OATH.md.

## What it buys

One `Ratchet` instance instead of two, so the laws are proven once. A core that compiles into an iOS app sold through the store, into a Swift or Kotlin SDK a company can license, and into a WebAssembly bundle. Forward secrecy and post-compromise security at every group size including two (L5, L6, L17), from a maintained library with published proofs of the MLS protocol.

## How we can charge

The AGPL has always permitted selling the software; what it forbids is withholding the source from the people you sell it to. So the open version can be sold as an app. Beyond that, the revenue that does not require a second licence is running ordered carriers (the relay queues groups need), hosting builder attestations and the transparency log for teams that want their own, support and indemnity, and integration work. The commercial licence is for the one thing the AGPL cannot do, which is let a company embed the core in an application whose source they keep.

## Alternatives rejected

Keep libsignal and ship iOS outside the store: loses most iOS users and still forbids commercial embedding. Keep libsignal and ask Signal for an exception: they have not granted one to anyone and the project would wait on a decision it cannot influence. Implement the Double Ratchet ourselves under MIT: forbidden by AGENTS.md rule one, and the first draft of this project explained why.
