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
| `unheld verify <name>` | `verify` | L3 | Prints the pairwise safety number, waits for the other side to read theirs aloud, and asks whether every group of digits matched. The default answer is no. Only a yes mints a `Peer`. A QR scan can fill the comparison and cannot replace it. |
| `unheld peers` | | L14, L18 | Every peer with its state: `Verified`, `Changed`, `Pending`, and in groups `Vouched by <name>`. |
| `unheld send <peer> [-c clipboard \| file \| stdout]` | `seal` | L4, L8, L14 | Reads the message from stdin or the editor, seals it, pads it to a bucket, and hands the blob to the chosen carrier. Refused for `Pending` or `Changed`. |
| `unheld open [-c clipboard \| file \| stdin]` | `open` | L11, L12, L13 | Takes a blob from the carrier, trial-decrypts across sessions, shows the message with its sender, and marks any gap in the sequence. A replayed or reflected blob is refused and counted. |
| `unheld log <peer> [--start N]` | | | Paged history with `total` and `next_start`; never truncated. |
| `unheld forget <peer> --older-than <duration \| count>` | `forget` | L10 | Deletes keys and messages older than the bound, by time and by count together. |
| `unheld wipe` | `wipe` | L10 | Destroys the vault. Also triggered by the duress passphrase at unlock. |
| `unheld devices list \| enroll \| revoke` | `enroll` | L15 | Phase 5. Enrolment shows the new device's fingerprint here and waits for yes. |
| `unheld group new \| add \| remove \| roster` | `start`, `add`, `remove` | L16, L17, L19 | Phase 5. Refuses a large group over an unordered carrier and says which carriers would do. |
| `unheld recover split \| join` | `split` | L21 | Phase 5. The interactive ceremony; shares shown once and never written. |
| `unheld about` | `install` | L22, L23, L24 | This version, its log entry, the builders who reproduced it, the signers and their jurisdictions, and the command to check it yourself. |
| `unheld mcp` | | | Runs the Model Context Protocol server over stdio (docs/MCP.md). |

## Carriers in the first release

`clipboard` puts the blob on the system clipboard and clears it after a configured interval; `file` writes or reads a path; `stdout` and `stdin` let the blob flow through pipes into any program. A blob is text-safe (base64url) so it survives every chat app and mail client we have met. The `relay` carrier arrives with Phase 5 and is the only ordered one.

## What is deliberately absent

There is no `--skip-verify`, no `--insecure`, no `--allow-changed`, no environment variable that alters a check, no remote configuration, no update command that installs anything on its own, and no way to export a private key except `recover split`.
