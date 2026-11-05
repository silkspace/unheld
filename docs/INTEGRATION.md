# Embedding unheld in your own application

Every app with a chat already has a transport: a backend, a websocket, a push channel, a database of messages. What it does not have is a way to make that backend unable to read them. unheld is that way. The core compiles into a library, your existing backend becomes a `Carrier`, and from that moment the company, its cloud provider and anyone who serves them a court order hold ciphertext of a fixed size and nothing else. This is the "bring your own carrier" model, and it is the whole integration story in one sentence.

## What you get

In the tree today: `unheld-core`, a Rust crate, with `unheld-blob` holding the `Carrier` trait and `unheld-carriers` holding a file, a pipe and a clipboard. A Rust service embeds the core, implements the trait over its own transport, and has the whole system below.

Specified, in this order, each a thin layer over the one crate so that anything that sees a plaintext stays Rust:

| Surface | Form | For |
|---------|------|-----|
| `unheld-py` | Python wheel built with PyO3, installed with `uv add unheld` | agent frameworks and backends that orchestrate but never hold keys |
| `unheld mcp` | Model Context Protocol server, see docs/MCP.md | assistants |
| `unheld-ffi` | UniFFI bindings: Swift package, Kotlin artefact | iOS and Android apps |
| `unheld-wasm` | WebAssembly bundle with a TypeScript interface | web apps and Electron |
| `unheld-ui` | verification, roster and key-change components for SwiftUI, Compose and React | the screens we do not let you leave out |

## What you implement

One trait with two methods. `put(blob)` sends a fixed-size byte array over your channel to the other party; `get()` yields the next one. You may answer `true` from `ordered()` if your backend sequences messages, which lets groups above the small-group threshold form (L19). That is the entire contract, and the trait is defined in a crate that cannot depend on any secret type, so your transport code cannot reach a key even by accident (L2).

## What you cannot leave out

The core's `send` takes a `Peer` whose state is `Verified`, and the only way to construct one is the verification ceremony, which needs a human answer to "do these digits match." Your app may draw that screen itself or use ours, but it cannot skip it, because no other constructor exists. The same holds for a changed key (L14), for adding a device (L15) and for roster changes, which arrive at every member as signed control messages your UI must show (L16). You can build an app that lies to its users about these states; the licence, the trademark policy and the oath are the remedy for that, and the type system is the remedy for everything short of it.

## What you can truthfully tell your users and your regulator

That you cannot read their messages, cannot be ordered to, and could not build a way to without shipping a different client, which the transparency log would show. That a removed group member reads nothing after removal. That the app's own vendor has no key. Few chat vendors can say any of that, and none can say the last.

## Licence and price

The core is AGPL v3 for anyone who publishes the source of what they build with it, and under a commercial licence for anyone who does not. The reasoning, including why the ratchet is OpenMLS rather than libsignal, is `docs/decisions/001-ratchet-and-licence.md`. Pricing is not decided; the shape will be a per-application licence with the source escrowed to the licensee, because an embedding whose supplier disappears must not strand its users. The things that need no commercial licence are running an ordered carrier for you, hosting your own transparency log and builder attestations, support, indemnity and integration work.

## A worked example

A telehealth app has patients and clinicians exchanging messages through its backend. Today the backend stores plaintext under encryption at rest, which means the company, its cloud and a subpoena can all read it. With unheld, the app generates an identity per user on device, the clinician and patient verify once at the first appointment by reading digits on a video call, the backend's message table becomes a `Carrier` that stores padded blobs, and the company's data-breach exposure for message content drops to zero because there is nothing in the table to breach. Nothing about the backend's scaling, push or storage changes except that it is now dumb.
