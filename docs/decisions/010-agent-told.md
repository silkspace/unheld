# 010: every message says whether an assistant reads the answer

**Status.** Accepted; in the tree as the `AGENT_READS` part of the payload, `Peer::agent_reads` and `Opened::agent_reads`. Written with the code. Closes the open item of `007-agent-surface.md`.

**Laws touched.** L18 (member standing shown), extended from a group's roster to the one other reader a pairwise conversation can have; L7 (unlinkability), which a field inside the encryption must not touch. Metadata rule: AGENTS.md rule 7 asks for a note on what an observer learns from anything added to a message, and this is that note.

## The question

`007-agent-surface.md` let a person point an assistant at a conversation, and the other person in it had no way to know but to be told by hand, which `grant-agent` asked the person to do. A correspondent who reads what you write, and may answer, is a member of the conversation in every sense that L18 cares about, and L18 says a member's standing is shown to everyone who writes to them, every time. The question is how the peer is told, by code rather than by courtesy, without the carrier or the relay learning that anything was said.

## The decision

**Every pairwise message says it.** The payload inside the encryption, which `009-queue-rotation.md` made a frame of a body and a part for a move, gains a second tagged part: one byte saying whether the person who sealed this message has let an assistant read and send with the one they are sending to. It is carried on every message between two people, true or false, so that no state is kept about what the peer has heard, a dropped message loses nothing that the next one does not say again, and a device that joins the identity later hears it on the first message it opens. A group message carries no such part, because the grant is per peer and a group's readers are a roster; what a group is told about assistants among its members is the open item below.

**The receiver records it and shows a change.** The core keeps, beside each peer, what that peer last said, and `open` returns `agent_reads` on a part only when the statement differs from what was kept: `Some(true)` the first time an assistant reads, `Some(false)` when it stops, `None` otherwise. The client prints a line on each change, `bob says an assistant reads what you send them`, and `unheld peers` marks such a peer `their agent` beside the `agent` mark of the person's own grant. `send` says, before sealing, `an assistant reads what bob receives`, which is the standing of a reader shown at the moment of writing, as `group send` shows every member's. The assistant's own server reports `agent_reads` in `peers_list`, so a model knows when the party across the conversation is also one.

**What an observer learns.** Nothing. The part is inside the encryption, inside the padding, and a message that carries it is the size it would have been without it; a sender's `inspect` shows what it showed before. A relay sees one more blob of a bucket size it has seen before. The peer learns one bit they are entitled to, that is the point, and nobody else learns that the bit was sent.

**The encoding has one form.** Tagged parts follow the body in ascending tag order, each at most once, with `MOVED_TO` a UTF-8 string and `AGENT_READS` a single byte that is 0 or 1. A tag repeated, out of order, unknown or with a value of another shape is a protocol error and the part is refused, because the sender is authenticated and a well-formed client never produces one; nothing is skipped or guessed at. The tags and the count are constants in `crates/core/src/config.rs`.

## What is in the tree

- `config::payload::{MOVED_TO, AGENT_READS, MAX_PARTS}`, `pack_payload` and `unpack_payload` in `crates/core/src/lib.rs`; `seal` packs the grant for the peer it seals to, `group_seal` packs none.
- `PeerRecord::agent_reads` in the vault, read as false when absent, so a vault written before this note opens as it did; `Peer::agent_reads` in the Rust, Python and `--json` views; `Opened::agent_reads` in Rust and Python.
- The lines in `unheld send`, `unheld open`, `unheld peers`, `grant-agent` and `revoke-agent`; `agent_reads` on each peer of `peers_list` in `docs/MCP.md`.
- Tests: a grant is heard once, on the next message, a revocation likewise, a message that says the same again says nothing new, the record survives a relock, and every malformed encoding is refused (`a_peer_is_told_inside_every_message_whether_an_assistant_reads_what_they_send`); the assistant's reply tells the peer and the assistant is told about the peer's own (`an_agent_reads_and_answers_only_where_the_person_granted_it_and_no_ceremony_has_a_tool`); the Python round trip of `agent_reads`.

## What is not here

A group told that an assistant reads one member's copy, which needs a word on which members and belongs with the group's rotation note. A grant narrower than a peer, or with a time limit, which would change what this one bit means. Whether the peer may refuse to be read by an assistant, which is a conversation between two people and not a rule the code should hold for them.
