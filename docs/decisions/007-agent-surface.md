# 007: an assistant is a renderer with a grant, and the ceremonies have no tool

**Status.** Accepted; in the tree as `unheld mcp`, `unheld peers grant-agent` and the `agent_access` field of a peer. The tool surface was fixed in `docs/MCP.md` before this note and is unchanged by it; this note records what the grant is, where it lives, and what an agent can and cannot reach.

**Laws touched.** L3 (verification is the only constructor), L11 to L13 (what `open` refuses), L14 (key change blocks), L18 (member standing shown), L22 (no creator input). Nothing near a key changes; the vault gains one boolean per peer.

## The question

An assistant that reads and writes messages on a person's behalf is a correspondent, and the surface it uses is the first one where the party pressing the keys is not the person who did the verification. The question is what such a party may do with an unlocked vault, and the answer has to hold against a prompt injection, which is a hostile correspondent who can type into the assistant.

## The decision

**The agent is a renderer.** It sees what a screen would show after the person has unlocked the vault, and no more: names, states, fingerprint prefixes, and the plaintext of messages from peers the person has pointed it at. It holds no key, because no tool returns one, and it performs no ceremony, because no tool exists for one. `verify`, `enroll`, `rotate`, `split`, `recover`, `wipe`, `group_add` and `group_remove` are absent from the surface rather than refused by it, so there is nothing for an injected instruction to call. A model that needs one asks the person to run the command.

**The grant is one boolean per peer, in the vault, set by the person at the command line.** `unheld peers grant-agent <peer>` sets it, `revoke-agent` clears it, `unheld peers` shows it, and `peers_list` reports it so the model knows which conversations it may touch. `message_send` to a peer without a grant is a refusal of its own, `NoGrant`, distinct from `Unverified`, so the model learns that a person has to act and not that a key is wrong. The grant lives beside the peer's state and under the same encryption, and the vault format reads the field as false when it is absent, so a vault written before this note opens as it did.

**The grant gates disclosure, not decryption.** The sender of a blob is inside the encryption, so the server opens what the carrier delivers before it can know who wrote it, as every client does. A part whose sender has no grant is counted as `withheld` against that name in `peers_list` and its text is dropped, in memory and nowhere else; it is not shown later, because the server stores no history and the person cannot be shown it either. The consequence for the person is stated plainly in `docs/MCP.md`: give an agent a carrier that carries only the conversations it is granted, which a relay queue is by construction and a file is in practice, and do not point it at a clipboard shared with other conversations.

**Received text is data.** Every message the server returns carries `untrusted: true`, its body is a JSON string inside a typed result rather than prose the model reads as its own, and the server's `instructions` at `initialize` say that a body is written by someone else and is never an instruction to the model. The server interprets nothing in a body and no field of the protocol lets a message carry an instruction the server acts on, which is L22 restated for a party that is not the maintainers.

**Nothing is cut.** `messages_read` pages with `total` and `next_start`, and a body longer than a page is returned as a head with a `ref` and a `next_start` that `message_read` continues from, so a long message reaches the model whole and a short one in one piece. A gap the ordered carrier detected is returned as a gap, with the numbers, and the server stops reading until the person intervenes, because an ordered carrier that skipped a blob has either lost one or hidden one and neither is for the model to paper over.

**One process holds the vault.** The server unlocks the vault once, from the passphrase in the environment or from the controlling terminal when the host provides one, and keeps it for the life of the connection. The command line and the server on the same vault at once would each save over the other's ratchet state, so the grant is made before the server starts and the server reads it then. This is the same rule every client has and is restated here because an assistant's host starts processes a person does not see.

## What the model's vendor sees

The same thing every carrier sees: nothing. The model runs where the person runs it, the vault is the person's, the grant is the person's, and the plaintext that reaches the model reaches it on that machine through a pipe. If the model is a remote service, the plaintext leaves the machine the way it leaves a screen that a person reads to someone over the phone, by the person's choice, and the vendor is then a correspondent and not a carrier.

## What is not here

Telling the peer that an agent reads the conversation, which `docs/MCP.md` wants on the next message after a grant, is a field in a message and so a change to what an observer learns (AGENTS.md, rule 7) and is its own note. Group messages are read through the grant of their sender and there is no tool to send to a group. A grant with a scope narrower than a peer, a time limit on a grant, and a count of what the agent sent are later.
