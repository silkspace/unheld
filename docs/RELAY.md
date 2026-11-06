# Running a relay

A relay is one static binary that holds queues of ciphertext and nothing else (`docs/decisions/006-relay.md`). Anyone can run one, and a relay the maintainers run has the same standing as any other, because every relay is designed as though it were run by the people its users are hiding from: it has no accounts, no names, no logs, and no answer a client would act on.

```
unheld-relay --dir /var/lib/unheld-relay init relay.example.org --port 4443
unheld-relay --dir /var/lib/unheld-relay serve --listen 0.0.0.0:4443
```

`init` makes an Ed25519 key and a self-signed certificate under `--dir` and prints the relay's address, `unheld-relay://relay.example.org:4443#<pin>`, where the pin is the SHA-256 of the certificate. Clients trust the pin and nothing else, so no certificate authority is a party and the certificate's names and dates do not matter. Give the address to the people who will use the relay. `serve` listens, one thread per connection, and forgets a queue thirty days after its last put.

## What a client does with it

A conversation's queues are held in a link file, and the two people in one each make the queue they will read (`docs/decisions/008-queue-per-direction.md`). `unheld relay new <address> <file>` makes a queue on the relay at `address`, with a random identifier and two random capabilities, keeps the one to read in `<file>`, and prints the one to write as an invitation, `unheld-relay://host:port/<queue>/<capability>#<pin>`. The relay holds hashes of the capabilities and never sees the preimages at rest. Each person hands their invitation to the other by any channel, the way an introduction travels, and runs `unheld relay join <file> <invitation>` with the one they received; from then on `-c relay:<file>` sends on the other person's queue and reads from their own, on relays each of them chose, and nothing either sends is handed back to them. The file also holds the reader's cursor.

A group uses one queue, because its commits need one order: whoever starts it runs `relay new`, does not join anyone, and hands the file itself to every member, each of whom passes `-c relay:<file>` to `group send`, `open`, `devices connect` and the rest. Every copy is a separate reader of the same queue, and a member's own blobs are skipped by number rather than fetched and refused.

A queue is the one carrier that orders, so a group above `config::group::SMALL` members forms over it and over nothing else (L19).

A queue between two people is read for a week or for 256 blobs, whichever comes first, and then its reader moves (`docs/decisions/009-queue-rotation.md`). The move happens inside the next message the reader sends: the client makes the next queue on the same relay and the message carries its write half inside the encryption, so the other person's client points at it on opening and nothing is handed over by hand. The old queue is read until a blob appears on the new one, which means the one writer has moved, and is then collected once more and deleted. Both limits are constants in `crates/relay/src/lib.rs`. A group's queue does not move this way, because a reader cannot know that every writer has moved; the admin moves a group by hand.

## What the relay sees and cannot do

It sees bucket sizes, times, the network addresses of those who connect, how many readers collect from one queue, and that every blob in one queue is one direction of one conversation. It cannot read a blob, forge one that opens, produce a roster change, or tell one person's queue from another's. A relay that drops a blob is caught by the reader's cursor, since numbers are dense, and a relay that serves two readers different orders forks their group into a refusal that is seen and not repaired.

## Limits

A queue holds 1024 blobs and takes 600 puts a minute, a relay holds 100 000 queues, and a connection silent for two minutes is closed. Each is a constant in `crates/relay/src/lib.rs`. A blob above the largest bucket, or of a length that is not a bucket, is refused at the door.

## On disk

Under `--dir`: `cert.der`, `key.der` (mode 0600) and `queues/<id>/` holding `write` and `read`, the two capability hashes, and one file per blob named by its number. There is no index, no database and no log, and a copy of the directory is a copy of ciphertext every carrier already had.
