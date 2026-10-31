# The command-line client

The first client is a terminal program because two people with laptops are the minimum viable product (TRACE.md) and because every later shell is this surface with pixels. Each command is one kernel verb or a view over the vault, each is total and fails closed with exit code 2 and a sentence, and there is no flag anywhere that weakens a check. `--json` on any command emits the typed result for scripts and for the MCP server, which is the same binary.

## Commands

| Command | Verb | Laws | What happens |
|---------|------|------|--------------|
| `unheld id new` | `gen` | L20 | Creates an identity in a new vault after the entropy health test passes; prints the fingerprint of the public key and nothing else. |
| `unheld id show` | | | The public fingerprint, the device list, the vault location, the entropy source. |
| `unheld id rotate` | `rotate` | L14 | New keys, a continuity statement signed by the old key, and every peer told on next send; the peer's client shows `Changed` until they re-verify. |
| `unheld intro export [--qr]` | `intro` | | The signed public bundle to hand over by any channel, as text or a QR code on the terminal. |
| `unheld intro import <file \| ->` | | L3 | Stages a pending peer. Sending to a pending peer is refused. |
| `unheld verify <name> [--qr]` | `verify` | L3 | Prints the pairwise safety number, waits for the other side to read theirs aloud, and asks whether every group of digits matched. The default answer is no. Only a yes mints a `Peer`. A QR scan can fill the comparison and cannot replace it. |
| `unheld peers` | | L14, L18 | Every peer with its state: `Verified`, `Changed`, `Pending`, and in groups `Vouched by <name>`. |
| `unheld send <peer> [-c clipboard \| file \| stdout]` | `seal` | L4, L8, L14 | Reads the message from stdin or the editor, seals it, pads it to a bucket, and hands the blob to the chosen carrier. Refused for `Pending` or `Changed`. |
| `unheld open [-c clipboard \| file \| stdin]` | `open` | L11, L12, L13 | Takes a blob from the carrier, trial-decrypts across sessions, shows the message with its sender, and marks any gap in the sequence. A replayed or reflected blob is refused and counted. |
| `unheld log <peer> [--start N]` | | | Paged history with `total` and `next_start`; never truncated. |
| `unheld forget <peer \| group>` | `forget` | L10 | Ends every session with the peer and deletes its keys; the peer stays verified and the next message starts a fresh session from a fresh introduction. For a group it deletes the local keys and leaves; the others list you until the admin removes you. The client stores no message history, so there is nothing else to forget. |
| `unheld duress` | | L10 | Sets a duress passphrase. Unlocking with it destroys the vault and answers exactly as a wrong passphrase would. |
| `unheld wipe` | `wipe` | L10 | Overwrites and removes the vault after a yes. |
| `unheld devices request` | | L15 | On a device with no vault yet: creates one with a device key and prints the request to hand to a device that has the identity, and the 60 digits this device shows. |
| `unheld devices enroll <name> <file \| ->` | `enroll` | L15 | On a device that has the identity: shows the digits the request's key makes, asks whether the new device shows exactly them, and only a yes produces the enrolment, the identity sealed to the new device alone. The default answer is no. |
| `unheld devices join <file \| ->` | | L15 | On the new device: opens the enrolment, becomes the identity with every verified peer, and prints what to hand back. |
| `unheld devices connect <file \| -> [-c dir:<path>]` | `add` | L15, L16 | On the witness: brings the new device into the ring, every session and every group, writing one commit per set of readers and one blob of welcomes for the device. Every peer's client prints `added 1 device`. |
| `unheld devices list`, `devices revoke <name> [-c dir:<path>]` | `remove` | L15 | The devices with the one you are on marked. Revoking writes one commit per session; the revoked device opens nothing sealed from then on and is told why. A device cannot revoke itself. |
| `unheld group new <name> <peer> <peer>... [-c]` | `start` | L16, L19 | Starts a group of verified peers with you as admin and writes the welcome every newcomer opens. Two people is a session, not a group. Above the small bound over an unordered carrier it refuses and says what the bound is. |
| `unheld group add <group> <peer> [-c] [-w]` | `add` | L16, L17, L19 | Admin only. Writes the commit for the members to `-c` and the welcome for the newcomer to `-w`; the newcomer opens nothing sealed before. |
| `unheld group remove <group> <member> [-c]` | `remove` | L16, L17 | Admin only. Writes the commit; the removed member opens nothing sealed after, and their client says who removed them. |
| `unheld group send <group> [-c]` | `seal` | L4, L8, L18 | Seals one blob every member opens, and first prints every reader with their state, so a vouched stranger is seen every time. |
| `unheld group roster <group>`, `group list` | | L18 | Every member as `Verified`, `Pending`, `Changed` or `Vouched` with the admin's name, and who the admin is. A joiner's group is named `g-` and the session hash until `group rename`. |
| `unheld recover split <k> <n>` | `split` | L21 | Shows `n` shares of the identity key one at a time, each once, clearing the screen between them, and writes nothing: the vault is byte for byte what it was. Any `k` rebuild the key; `k - 1` are nothing. |
| `unheld recover join <name> [files...]` | `join` | L21 | On a device with no vault: rebuilds the identity from `k` shares (files, or one per line on stdin) and makes a new vault with a fresh device key and no peers. Peers who verified you still do, since the key is the same; their names, the sessions and the device list are gone with the old vault. An altered share is refused and no vault is made. |
| `unheld inspect [-c stdin \| file:<path>]` | | L7 | Reads a blob with no vault and no key and prints everything a carrier could learn from it, so the metadata surface is measured rather than assumed. |
| `unheld about` | `install` | L22, L23, L24 | This version, its log entry, the builders who reproduced it, the signers and their jurisdictions, and the command to check it yourself. |
| `unheld mcp` | | | Runs the Model Context Protocol server over stdio (docs/MCP.md). |

## Carriers in the first release

`clipboard` puts the blob on the system clipboard or reads it from there, which is how a blob reaches a chat or a mail client; `file` writes or reads a path; `stdout` and `stdin` let the blob flow through pipes into any program; `dir:<path>` takes the commands that write one blob per set of readers, `devices connect` and `devices revoke`, and writes `<reader>.blob` for each. A blob is text-safe (base64url) so it survives every chat app and mail client we have met. None of these deliver in order, so a group above `config::group::SMALL` members is refused on all of them (L19); the `relay` carrier arrives with Phase 5 and is the only ordered one. A roster change in a group is a commit, and `open` prints it as a line every member sees: who added or removed whom, or that you were removed and the keys are gone (L16). How roster rights work and what a joiner does and does not know is `docs/decisions/003-groups.md`; how a second device becomes you is `docs/decisions/004-devices.md`.

## What is deliberately absent

There is no `--skip-verify`, no `--insecure`, no `--allow-changed`, no environment variable that alters a check, no remote configuration, no update command that installs anything on its own, and no way to export a private key except `recover split`.
