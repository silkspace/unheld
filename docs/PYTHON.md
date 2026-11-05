# unheld from Python

`crates/py` compiles the core into a Python module with PyO3, so that `import unheld` gives a program every verb the command line has, in the core's own vocabulary, with nothing added and nothing weakened. It is Rust compiled for the interpreter and not a Python reimplementation of anything: the only Python in the tree is the type stub that describes it and the tests that hold it to the laws.

## Build and install

```bash
cd crates/py
uv sync              # builds the module into .venv with maturin; needs the Rust toolchain
uv run pytest -q     # the laws from Python, with a list as the carrier
```

From another project, `uv add --editable <path to crates/py>` builds it the same way. The wheel is not on an index yet; it will be published when a release is in the transparency log, so that the wheel a program installs is the one anyone can rebuild.

## Python is the carrier

The Rust carrier trait has two methods, `put` and `get`, and from Python there is no trait at all, because the program is already in the position the trait describes. A verb that seals returns `bytes` of one of the bucket sizes in `unheld.BUCKETS`, a verb that opens takes them back, and whatever the program does with the bytes in between, a database row, a websocket frame, a queue on an unheld relay, a file, is its own transport. The transport sees ciphertext of a fixed size and nothing else, which is the whole integration story in `docs/INTEGRATION.md`.

Two verbs take `ordered`, a statement by the program that its transport delivers blobs in the order they were put. A group above `unheld.SMALL_GROUP` members forms only with it (L19), and a program that says `True` of a transport that reorders will see members refuse commits and fall out of step, which is the fork `docs/decisions/006-relay.md` describes and no carrier can repair.

```python
import unheld

alice = unheld.Core.create("vaults/alice", passphrase, "alice")
bob = unheld.Core.create("vaults/bob", passphrase, "bob")

alice.import_intro("bob", bob.intro())      # introductions travel by any channel
bob.import_intro("alice", alice.intro())
print(alice.fingerprint("bob"))             # both screens show the same sixty digits
alice.verify("bob", confirmed=answer)       # the human's answer; False is refused

blob = alice.seal("bob", b"hello")          # 1024 bytes, whatever the message
for part in bob.open(blob):                 # the session start and the message
    if part.body:
        print(part.sender, part.body)
```

## The surface

Every method is one core verb, named as the command line names it, with the laws it serves in its docstring and in `unheld.pyi`.

| Python | Verb | Laws |
|--------|------|------|
| `Core.create(dir, passphrase, name)`, `Core.unlock(dir, passphrase)` | `gen`, `unlock` | L20 |
| `core.intro()`, `core.import_intro(name, text)` | `intro` | L3 |
| `core.fingerprint(name)`, `core.verify(name, confirmed)` | `verify` | L3 |
| `core.peer(name)`, `core.peers()`, `core.grant_agent(name, granted)` | | L14, L18 |
| `core.seal(name, body)`, `core.open(blob)` | `seal`, `open` | L3, L4, L8, L11, L12, L13, L14 |
| `core.forget(name)`, `core.set_duress(text)`, `unheld.wipe(dir)` | `forget`, `wipe` | L10 |
| `core.group_new(name, peers, ordered)`, `group_add`, `group_remove`, `group_seal`, `roster`, `groups`, `group_rename` | `start`, `add`, `remove`, `seal` | L16 to L19 |
| `Core.create_device(dir, passphrase)`, `Core.request_fingerprint(text)`, `core.enroll(name, request, confirmed)`, `join_device`, `connect_device`, `revoke_device`, `devices` | `enroll`, `add`, `remove` | L15, L16 |
| `core.rotate()` | `rotate` | L14 |
| `core.split(k, n)`, `Core.recover(dir, passphrase, name, shares)` | `split`, `join` | L21 |
| `unheld.inspect(blob)` | | L7 |

A refusal is an `unheld.Refused` exception whose `reason` is an `unheld.Refuse`, the core's vocabulary as a Python enum, so a program compares with `is` and never matches on the sentence. The sentence is fixed per reason and never carries plaintext or key material.

Every verb that changes state writes the vault before it returns. There is a `save`, and nothing needs it: a program cannot roll a ratchet back by forgetting to call it, and so cannot open a blob twice.

## What Python sees and what it never sees

A program sees names, states, fingerprints, blobs, and the plaintext that `open` returns, which was written by someone else and is data to the program, never an instruction. It never sees a private key, a session state or the vault key, because no verb returns one. A share from `split` is a `Share` object whose bytes stay in Rust and are zeroised when the object is collected, and become a Python string only when the program calls `to_text` for the person who will hold it. The passphrase is the one secret that enters as a Python string, on its way to Argon2, and Python cannot zeroise a string, so a program keeps it out of logs and out of long-lived variables.

`verify`, `enroll` and `recover` take the human's answer or the human's shares as arguments, because this module is for the application that puts the human in front of the screen. A program that passes `confirmed=True` without asking has lied to its user, and that is where the type system stops and the licence, the trademark policy and the oath take over, as `docs/INTEGRATION.md` says of every embedding. An agent framework that embeds this module keeps those verbs out of the model's reach; the surface for an assistant is `docs/MCP.md`, which has no ceremony tool at all.
