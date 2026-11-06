# 008: one queue per direction, each on the relay its reader chose

**Status.** Accepted; in the tree as `Link`, `unheld relay new` and `unheld relay join`. Written with the code, which decided the file form and the invitation.

**Laws touched.** L7 (unlinkability) at the relay, L11 (no replay) and L12 (detectable omission) in the carrier, L19 (ordered or small) unchanged. Amends `006-relay.md`, which left the shape of a conversation's queues to this note and `IDEA.md`.

## The question

`006-relay.md` gave a conversation one queue: whoever made it held both capabilities, copied the file to everyone, and every holder appended to and collected from the same numbered sequence. That is what a group needs, since Messaging Layer Security wants one total order on commits and the relay's acceptance order supplies it. Between two people it is wrong twice over. The sender collects their own blobs on the next read, and the core refuses each of them, as it must, because a sender's own ratchet secret is gone the moment the message is sealed (L11); so every read on a shared queue ended in a refusal that was no one's fault, and the assistant surface of `007-agent-surface.md` had to be shown over a file. And a single queue means a single relay for both directions, chosen by whichever side made it, when `IDEA.md` says each person reads from a relay of their own choosing so that no relay sees a conversation, only a queue.

## The decision

**A link is a queue to send on and a queue to receive from.** What the carrier file holds is no longer one queue with two capabilities but two halves, each a relay, its pin, a queue identifier and the one capability this holder has for it, plus the cursor on the receive half. `unheld relay new <address> <file>` makes the holder's own queue on the relay they chose, keeps its read capability in `<file>`, and prints the write half once as an invitation, `unheld-relay://host:port/<queue>/<capability>#<pin>`, which says where, which, and the right to one verb on it. The other person runs `unheld relay join <their file> <that invitation>`, which points their send half at it, and does the same in return. After both have joined, each reads a queue only the other writes, on a relay only they chose, and nothing either sends is ever handed back to them. The invitation travels as the introduction does, by any channel, because holding it lets someone append blobs that `open` refuses and nothing else.

**A group keeps one queue, and a holder skips what it wrote.** A fresh link from `relay new` has both halves on one queue, which is the group form, and the file is handed to every member as before. The relay answers every `put` with the number it assigned, so a holder whose send and receive halves name the same queue records that number and, when the cursor reaches it, moves past without a `get`. Nothing is fetched and discarded, nothing is hidden: the holder knows what sits at that position because it put it there, and a number the relay serves out of sequence is still refused before the core sees the blob (L12). The two forms are one type and one carrier, and which one a link is follows from its halves rather than from a flag.

**What the relay learns, before and after.** Before, a relay saw one queue per conversation, with both directions in it, and so saw the whole shape of a two-person exchange: who answered whom, how fast, how often. After, a relay that holds one person's inbound queue sees one direction of one conversation and the network addresses of its one writer and its one reader, which is less. A relay both sides happen to choose still sees both queues, and can join them by timing; that is the linkage `006-relay.md` accepted, now split across two identifiers rather than one, and queue rotation remains the remedy. For a group nothing changes: one queue, one roster-sized set of readers, the count and not the members. A relay learns nothing from a skipped number, because a skip is a `get` that is never sent.

**The three verbs are untouched.** Create, put, get and delete are what they were in `006-relay.md`, the wire format is byte for byte the same, and the fuzz target over it stands. Everything here is in the client's file and in which capability it presents where.

## What is in the tree

- `Link`, `Half` and `Endpoint` in `crates/relay/src/carrier.rs`, the file form with `send`, `receive`, `after` and `mine`, the invitation as text, and `Transport::call` taking the endpoint so one carrier reaches two relays.
- `unheld relay new`, which prints the invitation, and `unheld relay join`, which takes one; `docs/RELAY.md` and `docs/CLI.md` say how a pair and a group each set up.
- Tests: two people over TLS hold two queues and each reads only what the other wrote, a link that only sends refuses to read, a shared queue's holder skips what it wrote and is still caught by a drop (`crates/relay/src/carrier.rs`); two cores over two relays exchange messages with no refusal and each store holds one queue (`crates/cli/tests/relay.rs`); the assistant of `docs/MCP.md` reads and answers over a relay and the person's own reply never returns to them (`crates/cli/tests/mcp.rs`).

## What is not here

Queue rotation, which this note makes simpler, since a rotation is now a new invitation handed inside a message rather than a new file handed to everyone. A relay list, so that `relay new` picks from relays the person has entered rather than taking an address each time. Several relays per direction. The onion transport. Each of these is still its own note.
