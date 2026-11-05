# 002: what a carrier can read through the padding

**Status.** Accepted for the overlay; the relay queue design, `006-relay.md`, adds queue-level linkage of the same kind and accepts it on the same terms.

**Laws touched.** L7 (unlinkability) is stated precisely rather than loosely; L13 is unchanged; the introduction carries no name.

## The question

The kernel says a blob carries no header the system adds, and the proof of concept pads a Messaging Layer Security message into a bucket. MLS has framing of its own, and the question is what a carrier can read through our padding, and whether that is acceptable for the overlay.

## What is in the clear, measured

`unheld inspect` reads a blob the way a carrier would, with no vault and no key, and a test pins what it finds so a change cannot widen it silently. For an application message the carrier can read the protocol version and wire format, a 32-byte random session identifier, the epoch number and the content type. The sender and the content are encrypted. For a welcome the carrier can read the ciphersuite, the number of recipients and a hash of each recipient's introduction, which a carrier that also saw the introduction can match. For an introduction, which is public by design, the carrier reads a key package; it contains no name, because the credential identity is sixteen random bytes and names live only in the vault that chose them.

## The decision

For the overlay this is accepted and recorded. The carriers it uses already know both endpoints, so the session identifier adds linkage within a conversation and does not reveal one, and the epoch counts updates rather than messages. The relay queue design in the next phase is where linkage between blobs is handled by construction, and this note is reopened when that design is written. Until then the gap is listed in TRACE.md, measured by `inspect`, and held by a test.

## What changed now

- The credential identity in every key package is random, so an introduction carries no name (test: `introduction_carries_no_name`).
- `unheld inspect` reports what an outsider reads from a blob, in prose or as JSON.
- A test asserts the exact set of fields exposed and that two blobs of one session share the identifier, so the leak is a number in the test suite rather than a sentence in a document.
