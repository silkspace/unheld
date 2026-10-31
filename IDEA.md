# unheld: a threat-model-first communications platform

This is the idea document. It says why we are building, what we are defending against, what we are not, and how the pieces fit. AGENTS.md says how to work in the repository and CLAUDE.md is the map of the code. Read this one first and argue with it, because every design choice below is a consequence of the threat model, and if the threat model is wrong the design is wrong with it.

## The premise

Signal, WhatsApp and Telegram are compromised, and the detail of how decides what to build. The cryptography inside Signal and WhatsApp (X3DH and now PQXDH for the handshake, the Double Ratchet for sessions, Sealed Sender for the envelope) has been studied for a decade and is not where anyone has been caught. What has been caught, repeatedly, is everything around it.

The identity layer is a phone number, which is a government-issued, carrier-controlled, SIM-swappable identifier that links every account to a legal person and to a telco's location records. Signal added usernames in 2024 but still requires a number to register, and WhatsApp is the number.

The metadata layer sees who talks to whom and when. WhatsApp's own engineers wrote in 2024 that a government with network visibility could work out who is talking to whom from traffic patterns alone, and Meta holds the social graph in the clear. Signal's servers see IP addresses and timing even with Sealed Sender, and Signal runs on a handful of large clouds that are easy to subpoena or tap at the border. Push notifications through Apple and Google are a metadata side channel that both companies confirmed in late 2023 they hand to governments on request.

The endpoint is where the real compromises happen. Pegasus, Predator and Graphite read messages off the screen of a phone that has already been taken, and no protocol survives that. Paragon's Graphite was used through a WhatsApp zero-click against journalists and activists in early 2025. The Signal linked-device feature was phished at scale in 2025 by Russian-aligned groups who got targets to scan a QR code that added the attacker's machine as a device. In the same year a cloned Signal client that archived messages to a third-party server was found running on senior United States officials' phones and the archive server was breached within weeks. None of that touched the Double Ratchet.

The operator is a legal target. Telegram is not end-to-end encrypted by default at all, its secret chats exist only one to one on mobile, and after its founder's arrest in France in 2024 it changed policy to hand over phone numbers and IP addresses on request. Signal, which holds almost nothing, has still had to threaten to leave the United Kingdom and Sweden over proposed scanning and backdoor laws, and Apple withdrew its encrypted iCloud backup from the United Kingdom in 2025 rather than build a backdoor. Where an operator can be compelled, it will be.

The distribution channel is a chokepoint. Every one of these apps reaches a phone through two app stores that can be ordered to serve a different build to one account, and most users cannot verify what they installed.

The conclusion is not "the crypto is broken, write new crypto", since writing new crypto is the one move that would make things worse. The conclusion is that a platform is only as private as its weakest layer, and the weak layers are identity, metadata, endpoint, operator, distribution and the human. We hand-roll the architecture and reuse every primitive.

## Who holds the keys

The first question anyone should ask of a messenger is whether a party other than the two people talking can ever produce the key, by court order or by a mole in the operator's staff. The answer differs more than the marketing suggests. Telegram holds the keys for every normal chat and group and only its one-to-one secret chats on mobile are end-to-end encrypted, so the operator can be ordered or bribed into opening almost everything. Signal and WhatsApp generate keys on the device and the operator never sees a private key, which is why Signal's published subpoena responses contain nothing but a registration date and a last connection date. Proton and Tuta hold the user's private key encrypted under the user's password, which is safe only as long as the password is strong and the web client they serve is honest. Cloud backups are the back door most people actually walk through, because a WhatsApp history backed up to iCloud or Google Drive without the end-to-end option is readable by Apple or Google under an ordinary warrant.

Classic PGP with a key generated in a local app (iPGMail, PGPro or OpenKeychain on a phone, GnuPG or Sequoia on a desktop) solves key custody completely, since the private key never exists anywhere but the device, and that is the whole of its appeal. It gives up forward secrecy, so one compromised key opens every message ever received; it leaves sender, recipient, time and usually the subject in the clear; it depends on the user comparing fingerprints by hand and on never quoting a plaintext in a reply; and it moves trust from an audited open protocol to whichever app does the decrypting. It is strictly better than Telegram, roughly equal to Signal on custody, and worse than Signal on everything else.

The design consequence for us is that key custody is necessary and not sufficient, and that the cheapest way to make the question unanswerable is to have no operator at all. The first product is therefore an overlay with no server: keys generated on device, introduction by an out-of-band fingerprint the app refuses to proceed without, sessions over libsignal for forward secrecy and post-compromise security, and the ciphertext carried as a pasteable blob or share-sheet payload over whatever channel the two people already use. Nobody can be compelled because nobody holds anything. The relay network, padding and onion transport described below are the second product, and they exist to solve the metadata problem, which neither the overlay nor PGP touches.

## The threat model

We name adversaries by tier and say for each whether we defeat it, degrade it, or only survive it. A design that claims to defeat everything is lying, and a user who believes it will take risks they should not.

| Tier | Adversary | What we do |
|------|-----------|------------|
| T0 | Passive observer on the network path (ISP, hotel wifi, border tap) | Defeat. Everything on the wire is ciphertext of a fixed size at irregular intervals, carried over an onion-routed or mixed transport. |
| T1 | Active network attacker (MITM, injection, blocking) | Defeat the first two by authenticated transport and pinned keys; survive blocking by pluggable transports and multiple relays. |
| T2 | Hostile relay operator, including us | Defeat. A relay stores and forwards opaque blobs addressed to per-contact queues. It cannot read content, cannot link two queues to one person, and cannot tell a message from padding. |
| T3 | Legal compulsion of the operator | Defeat by holding nothing worth compelling. There is no account database, no contact graph, no phone numbers, and anyone can run a relay, so there is no single party to order. |
| T4 | Platform vendor (Apple, Google, the OS) | Degrade. Reproducible builds with a public transparency log, no vendor push payloads, keys in the hardware enclave where one exists, and a desktop and sideload path that does not depend on a store. |
| T5 | Targeted endpoint compromise (Pegasus class) | Survive. We cannot stop a kernel exploit. We limit the blast radius: short-lived messages by default, no cloud backup, per-conversation keys that rotate on every message, a duress unlock that wipes, and a linked-device model that cannot be phished with a QR code. |
| T6 | Device seizure and coercion | Survive. Full local encryption under a key the device cannot produce without the user, deniable authentication so a transcript proves nothing, disappearing messages, and a panic gesture. |
| T8 | The creator (us), compelled, bribed, hacked or wrong | Defeat for the protocol, since no verb takes an input we hold at runtime and there is no server, directory or remote switch; degrade for the binary, through reproducible builds attested by independent builders, threshold release signing across jurisdictions, a public transparency log the client checks before install, and no forced update. On iOS only Apple can check what Apple shipped, and we say so. |
| T7 | The other party | Out of scope. If your correspondent is compromised or hostile, nothing anywhere helps. We make it obvious who you are talking to and hard to be impersonated, and we stop there. |

The most important row is T7, because most "the app was hacked" stories are actually "the person on the other end was." We do not pretend otherwise.

## Principles

1. **Never invent a primitive.** Every piece of cryptography is a vetted construction from a maintained, audited library: the Signal protocol (PQXDH plus Double Ratchet) or the Noise framework for pairwise sessions, Messaging Layer Security (RFC 9420) with a post-quantum hybrid for groups, and libsodium or the RustCrypto crates underneath. What we design is the shape around them: identity, queues, transport, padding, storage and the client.

2. **The server is the adversary.** Every relay is designed as though it were run by the people we are hiding from. It holds nothing that would help them, it cannot distinguish users, and it is replaceable by anyone with a VPS or a Raspberry Pi. We run relays as a convenience, not as a trust anchor.

3. **No global identity.** There is no phone number, no email, no username directory, no central key server. Identity is a long-term signing key, and contacts are made by exchanging introductions out of band (a QR code in person, a link over an existing channel, a one-time invitation). Each contact pair gets its own unidirectional queues on relays of each side's choosing, so no relay sees a user, only a queue. SimpleX proved this model works at consumer scale and we adopt it rather than argue with it.

4. **Metadata is content.** Messages are padded to one of a small set of fixed sizes, sent at jittered times, optionally interleaved with cover traffic, and carried over Tor onion services by default with a mixnet transport as an option. Receipts, typing indicators and presence are off until a user turns them on, per contact.

5. **The endpoint is hostile tomorrow.** We assume every device will eventually be compromised and ask what the attacker gets. The answer should be: the current session's recent messages and nothing older, no backups, no key that unlocks history, and no way to silently add a device. Forward secrecy and post-compromise security are not features, they are the design.

6. **Memory safety is not optional.** Everything that touches a key or a plaintext is written in Rust with a minimal, pinned, audited dependency tree. There is no third-party analytics, advertising, crash-reporting or telemetry SDK in any client, ever, and a test fails if one appears in the lock file.

7. **Builds are reproducible and transparent.** Every release is built reproducibly from a tagged commit, signed, and recorded in a public append-only log so that two users can check they run the same bytes and a targeted build would be visible.

8. **Deniable, ephemeral, local.** Messages expire by default. Nothing is backed up to anyone's cloud. Local storage is encrypted under a key derived from the user's secret plus the hardware enclave, with an optional offline recovery split across trusted people using Shamir shares. Authentication is deniable in the Off-the-Record sense, so a leaked transcript is not evidence.

9. **Humans are the last layer.** The interface makes safety numbers unavoidable, shows every linked device and every relay in use, and refuses to add a device without a second confirmation on an existing one. Dangerous defaults do not exist; dangerous options are labelled as such.

10. **Open, audited, boring.** All code is public, the threat model is public, and before any release is called stable it has had an external audit whose report is published whole, including what was not fixed.

## Architecture

The system has six layers, and each is replaceable without touching the others.

**Identity.** A user is an Ed25519 signing key plus an X25519 (and ML-KEM-768) key agreement key, generated on device and never leaving it except as Shamir shares the user explicitly makes. There is no account. A contact is a record of the other party's keys, a human-chosen pet name, and the pair of queues used to reach them. Introductions are signed invitation blobs carried out of band.

**Session.** Pairwise sessions use the Signal protocol via the libsignal Rust crate (PQXDH handshake, Double Ratchet, Sealed Sender envelopes). Groups use Messaging Layer Security through OpenMLS with a hybrid post-quantum ciphersuite, which gives forward secrecy and post-compromise security for groups at logarithmic cost rather than the pairwise fan-out WhatsApp uses. Attachments are encrypted under a one-time key and stored on a relay as an opaque blob referenced from the message.

**Queue.** Every contact pair has two unidirectional queues, one per direction, each on a relay chosen by the receiver. The sender holds a send-capability for the queue, the receiver a receive-capability, and the relay can verify both without learning who holds them. Queues rotate on a schedule so a long-lived observer cannot build a profile of one.

**Relay.** A relay is a small Rust service that accepts a blob for a queue it recognises, holds it until collected or expired, and forgets it. It keeps no logs, no accounts, and no state beyond the queues and their expiry. It is published as a container and a single static binary so anyone can run one, and the client picks relays from a user-editable list, defaulting to several run by different parties in different jurisdictions.

**Transport.** Clients reach relays over Tor onion services by default, using the Arti Rust implementation embedded in the client so there is no separate Tor process to misconfigure. Direct TLS is available for users who choose speed over cover, and a mixnet transport is a planned option. Pluggable transports handle censorship, and a local mesh over Bluetooth and wifi direct lets nearby devices exchange messages with no network at all, as Briar does.

**Client.** A shared Rust core (identity, sessions, queues, storage) behind a narrow typed API, with thin native shells: a command-line client first, then desktop, then mobile. The core never hands a plaintext or a key across the API boundary to anything but the renderer, the renderer has no network access, and the whole process is sandboxed as tightly as the platform allows.

## How this differs from what exists

| Property | Signal | WhatsApp | Telegram | unheld |
|----------|--------|----------|----------|------------|
| Identity | Phone number (plus username) | Phone number | Phone number | Keypair only, no directory |
| Content encryption | Signal protocol, PQ hybrid | Signal protocol | None by default | Signal protocol and MLS, PQ hybrid |
| Group encryption | Pairwise fan-out | Pairwise fan-out | None | MLS |
| Server sees | IPs, timing, number | IPs, timing, number, social graph | Everything | Opaque queues, padded blobs |
| Transport | Direct TLS, optional proxy | Direct TLS | Direct | Onion-routed by default, mesh offline |
| Who can run a server | Signal | Meta | Telegram | Anyone |
| Push notifications | Apple and Google | Apple and Google | Apple and Google | None through vendors; own wake channel |
| Backups | Optional, local or paid cloud | Cloud, often unencrypted | Server-side | Local only, user-held key, Shamir recovery |
| Builds | Reproducible on Android | Closed | Partially open client | Reproducible, transparency log |
| Linked devices | QR scan, phishable | QR scan | Login code | Second-device confirmation, out of band |
| Deniability | Yes | Yes | No | Yes |

## What we borrow rather than build

We are hand-rolling the platform, not the parts, and we should say plainly where the parts come from so that a reviewer can check them.

- **libsignal** (Rust) for PQXDH, the Double Ratchet and Sealed Sender. Signal Foundation maintains it and it is the most reviewed implementation in existence.
- **OpenMLS** (Rust) for group messaging, with a hybrid ML-KEM ciphersuite.
- **Arti** (Rust) for embedded Tor.
- **The SimpleX queue model** as a design, re-implemented against our own relay protocol so the trust boundary is ours.
- **Briar's mesh transport** as a design reference for offline exchange.
- **Sigstore or an equivalent transparency log** for release signatures.
- **libsodium / RustCrypto** for every hash, key derivation and symmetric primitive, pinned and audited.

If at any point one of these does what we need, we use it rather than reproduce it. The temptation to rewrite a ratchet "to understand it" is the single most dangerous idea in this repository and AGENTS.md forbids it.

## What we will not fix, and say so

We cannot defend a device whose kernel belongs to someone else; we can only make the haul small. We cannot stop a correspondent from screenshotting, forwarding or being arrested. We cannot make Tor fast or make onion-routed voice calls pleasant, so calls will come late and will be honest about their latency. We cannot make a system with no phone-number discovery as easy to adopt as one that reads your contacts, and we accept that this is for people who need it rather than everyone. We cannot prevent a sufficiently motivated state from blocking all relays in a country, only make it expensive and provide a mesh fallback. Every one of these appears in the user-facing documentation in plain words.

## Roadmap

**Phase 0, design (now).** This document, a written threat model with the tiers above, a protocol specification for queues and relays, and an outside read of both before any code that touches a key is written.

**Phase 1, the overlay (the minimum viable product; acceptance criteria in TRACE.md).** The Rust core: identity, pairwise sessions over libsignal, local encrypted storage, and a client that encrypts to a pasteable blob and decrypts one, with fingerprint verification that cannot be skipped. A terminal client first, then thin iOS and Android shells with a share sheet. No server exists in this phase, so there is nothing to compel. Property tests and fuzzing from the first commit.

**Phase 2, relay and transport.** The relay client over plain TLS to a single relay, then the relay as a static binary and container, queue rotation, padding and jitter, Arti embedded, and a relay list with several operators. Adversarial tests that run a malicious relay against the client.

**Phase 3, groups and attachments.** OpenMLS with the hybrid suite, encrypted attachments as opaque relay blobs, and the linked-device protocol with second-device confirmation.

**Phase 4, desktop and mobile shells.** Thin native shells over the core, hardware-backed key storage, duress unlock, reproducible builds and the transparency log.

**Phase 5, audit and release.** An external audit of the core, relay and transport, with the report published in full, then a first stable release. Mesh transport and a mixnet option follow.

## Open questions

Whether to use libsignal directly or Noise plus our own queue binding is the first real decision; libsignal gives us Sealed Sender and the PQ handshake for free but ties us to Signal's wire types, so we lean towards libsignal and a thin adapter. How much cover traffic a phone can afford on battery is an empirical question for Phase 2. Whether to offer any discovery at all beyond out-of-band introduction, even an opt-in rendezvous, is a question for users of the Phase 1 client. How the recovery shares are encoded for people who are not technical, and whether a social recovery that does not leak the social graph is even possible, is open.
