# 009: a queue is read for a while, then its reader moves

**Status.** Accepted; in the tree as `Link::due`, `RelayCarrier::rotate`, `Core::seal_moved` and `Opened::moved_to`. Written with the code.

**Laws touched.** L7 (unlinkability) at the relay, which is what rotation is for; L11 (no replay) and L12 (detectable omission), which the retirement of a queue must not weaken; L13 (bounded state), since a move adds nothing a relay keeps. Closes the open item of `006-relay.md` for two people; a group's queue is below.

## The question

A relay sees that every blob in one queue is one direction of one conversation, and `006-relay.md` accepted that with rotation as the remedy: a queue that is read for a bounded time and then abandoned gives a long-lived observer a bounded profile. `008-queue-per-direction.md` made the reader of a queue its owner, so the one who can retire a queue is the one who reads it, and the question is how a reader moves to a fresh queue without a hand-over of files, without losing a blob in flight, and without the relay learning anything from the move but the move.

## The decision

**The reader moves, on a schedule that is code.** A link records when its queue was made and how many blobs have been collected from it, and `due` is true once either passes a constant in `crates/relay/src/lib.rs`. The check runs when the person, or the assistant acting for them, next sends: the client makes the next queue on the same relay, holds both its halves as `next`, and seals the message. Nothing runs on a clock, because the client is not a daemon, and nothing in the protocol asks the relay for a date.

**The invitation rides inside the message.** An application message is now a frame of one or two parts inside the encryption: the body, and when the sender is moving, the write half of the next queue in the carrier's own words. `Core::seal_moved` puts it there and `Opened::moved_to` brings it out, and the core never reads it; the client hands it to the carrier the spec names, which points its send half at the new queue. Every message carries the invitation until the move is complete, so a message the peer never opens does not strand the move, and a peer who already moved is told nothing new. The padding hides that anything was added, and a sender's `inspect` shows what it showed before.

**The old queue is retired only when it is known to be finished.** The reader collects from the old queue first, and looks at the next one only when the old says nothing. A blob on the next queue means its one writer has moved, and a writer moves before writing there, so everything they wrote to the old queue is already in it: the reader looks once more, collects a straggler if there is one, and otherwise deletes the old queue and makes the next one current. The first blob on the next queue is returned at that moment and not before, so no cursor moves past a blob that was not handed over. Order across the two queues is the writer's order, a dropped number on either queue is still refused before the core sees it, and the relay is never asked for a date, a count or an opinion.

**What the relay learns.** It sees a new queue made from the reader's address at about the time a message is read, and later a deletion of the old one, so a relay that watches addresses can join the two queues; the onion transport is what takes the address away, and until then rotation bounds what a passive observer of the queues learns rather than what the relay itself can infer. It learns nothing about the message that carried the invitation, since the message is the size it would have been. A move costs one `create` and one `delete`, and leaves the relay holding what it held.

**A group's queue does not rotate here.** A group's queue has many writers, and a reader cannot know that all of them have moved without an acknowledgement from each or an expiry, so the inference above does not hold. The group's queue is left where `006-relay.md` put it: the admin moves the group by hand, a removed member with the write capability can fill the old queue up to its depth and no further (L13), and a rotation inside a commit is still the open item. The code refuses to rotate a shared queue rather than guess.

## What is in the tree

- `config::payload` and `pack_payload` in the core, `seal_moved`, `moved_to` on `Opened` and in the Python module as a keyword argument and a field.
- `Link::since`, `Link::next`, `Link::due`, `Link::moving_to` and `RelayCarrier::rotate` in `crates/relay/src/carrier.rs`, `config::rotate` in `crates/relay/src/lib.rs`, and the take-over in `get`.
- `seal_over` and `follow_move` in the client, used by `unheld send`, `unheld open` and the assistant server, which reopens its link after either.
- Tests: a reader whose queue is due moves, the writer follows on the next open, a straggler on the old queue is collected before the first blob on the new, the old queue is gone from the relay, and a shared queue refuses to rotate (`crates/relay/src/carrier.rs`, `crates/cli/tests/relay.rs`); the Python round trip of `moved_to`.

## What is not here

Rotation of a group's queue, which needs a way to know every writer has moved. Moving to a different relay, which needs the relay list of `008-queue-per-direction.md`. A forced move by the person, outside the schedule. The onion transport, without which the relay can still join two queues by the address that made them.
