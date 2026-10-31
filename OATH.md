# OATH.md: what the people behind unheld commit to

The protocol is designed so that nobody has to trust us, and this file exists because that is never entirely true. Someone writes the code, someone signs the release, someone runs the default relays, someone answers the subpoena. This is what those people promise, in words a user can hold us to and a court can read. Every maintainer signs this file with the key they sign releases with, and the signatures are in the transparency log beside the first release they sign.

## To the people who use it

We will never hold a key that can open your messages, and we will design so that we could not build one if ordered. We will never add a way to read, scan, filter, flag or report content, on the device or off it, for any reason, including reasons we agree with. We will never add a feature that is on by default and makes you less private than the version before it. We will never run telemetry, analytics or crash reporting, and we will never embed code from anyone who does. We will never add a member to a group, a device to an identity or a key to a contact, because the protocol gives us no way to and we will keep it that way.

We will tell you what we cannot protect, in the application on the first run and in every document, in plain words: a device someone else controls, a correspondent who is careless or hostile, and a person being coerced.

If we are ordered to break any of this, we will refuse, publish the order where the law allows, publish the fact of it where the order forbids the text, and shut the project down and hand it to a fork before we comply. The protocol has no operator, so the shutdown costs you nothing but our names on the releases.

## To each other

No one of us can ship a release alone, and we will keep the signing threshold above one and the signers in more than one country. No one of us merges their own change. Every change near a key starts as a written design note that names the laws it touches. We publish every audit in full, including the findings we did not fix. We publish the formal model and keep it in step with the code. We disclose every vulnerability we learn of, with a fix or without one, within the window in `docs/MAINTAINERS.md`, and we never pay or accept payment for silence.

We hold our own machines to `docs/MAINTAINERS.md`. Release keys live on hardware tokens, never on a laptop, never in a password manager, never in a cloud. No automated agent of any kind, including the coding assistants we use every day, holds a signing key, a release credential, a relay deploy token or a user's data, and no commit written by one is merged without a human reading the diff.

## To the record

When we get it wrong, we say so in the same place and at the same volume as we said we had it right. The changelog records what weakened as carefully as what improved. A fork that keeps these promises is us, and a release of ours that breaks them is not.

Signed by each maintainer with their release key; see `docs/MAINTAINERS.md` for the key fingerprints and the log entries.
