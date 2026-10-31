# 004: devices of one identity

**Status.** Accepted for the overlay.

**Laws touched.** L15 (enrolment needs a witness), L16 (no ghost), L3 (no skip), L14 (key change blocks).

## The question

An identity is one signing key that peers verify by comparing digits, and a session in Messaging Layer Security is a tree of leaves each signed by its own key, with the rule that no two leaves share one. A person with two devices therefore needs two leaf keys and one identity, and the question is how a peer's client knows that two leaves are one person, how a new device comes to hold the identity, and what stops the 2025 attack where a victim scans a code that enrols an attacker's device.

## The decision

**A certificate in every credential.** Each device has its own signing key, and the credential on every leaf it holds is a certificate, signed by the identity key, over the identity key, the device key and the day of enrolment. A peer's client reads a leaf as a person by checking that certificate under the identity key it verified, so the roster shows one name with however many devices, and a leaf whose certificate does not hold belongs to nobody. The device's name is not in the certificate, because a key package is public by design and an introduction carries no name.

**The witness sees the digits.** A new device creates a vault with a device key and an encryption key and prints a request, together with sixty digits of its device key. A device that already holds the identity reads the request, prints the digits the request's key makes, and asks whether the new device shows exactly them, with no as the default. Only a yes produces the enrolment, which is the identity key, the device certificate, the device list and every peer with their verification state, sealed with hybrid public-key encryption to the key that exists on the new device alone. A request the carrier made up has no screen for the witness to compare against, which is the whole of L15 and is the lemma `device_needs_witness` in `formal/`.

**Four hands, not two.** The new device cannot produce introductions until it holds its certificate, and the witness cannot bring a device into a session without one introduction per session, since a key package is single use. So after `request` and `enroll` come `join`, which opens the enrolment and prints one introduction for each session the witness announced plus one for the ring, and `connect`, which adds the device to each and writes one commit per set of readers and one blob of welcomes for the device. Blobs for different readers never share a blob (L8).

**A device change is not a roster change.** Any member may add or remove leaves whose certificate names their own identity, in a pairwise session as in a group, and every client prints `added 1 device` or `removed 1 device` for it. Adding a leaf whose certificate names anyone else is a roster change and falls under the admin rule, and in a pairwise session is refused outright, so nobody turns a conversation into a group by calling the newcomer a phone.

**A ring among your devices.** The devices of one identity share a session of their own, created when the second device joins. Nothing a peer could read travels on it; it exists so a revocation reaches the revoked device and so a later key rotation can hand the new identity key to the other devices without a peer in the room.

**Equal devices.** Every enrolled device holds the identity key and can witness, enrol and revoke. A stolen enrolled device is therefore the whole identity until another device revokes it, and the thief can race to revoke yours. The alternative, one primary device that alone holds the identity key, is the Signal model, and it fails the moment the primary is lost; TRACE.md lists this as the open question it is.

## What is not here

Rotation of the identity key, with a continuity statement signed by the old key and the new key handed to the other devices over the ring, is the next verb on this surface. Recovery shares split the identity key only, so a recovered identity has its peers' trust but no sessions and no device list. Vault files written before this decision are refused in words rather than migrated, since nothing before 0.1 is kept.
