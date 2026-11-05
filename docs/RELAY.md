# Running a relay

A relay is one static binary that holds queues of ciphertext and nothing else (`docs/decisions/006-relay.md`). Anyone can run one, and a relay the maintainers run has the same standing as any other, because every relay is designed as though it were run by the people its users are hiding from: it has no accounts, no names, no logs, and no answer a client would act on.

```
unheld-relay --dir /var/lib/unheld-relay init relay.example.org --port 4443
unheld-relay --dir /var/lib/unheld-relay serve --listen 0.0.0.0:4443
```

`init` makes an Ed25519 key and a self-signed certificate under `--dir` and prints the relay's address, `unheld-relay://relay.example.org:4443#<pin>`, where the pin is the SHA-256 of the certificate. Clients trust the pin and nothing else, so no certificate authority is a party and the certificate's names and dates do not matter. Give the address to the people who will use the relay. `serve` listens, one thread per connection, and forgets a queue thirty days after its last put.

## What a client does with it

`unheld relay new <address> <file>` makes a queue on the relay, with a random identifier and two random capabilities, one to append and one to read, and writes all of it to `<file>`. The relay holds hashes of the capabilities and never sees the preimages at rest. The person who made the queue hands the file to everyone in the conversation, the way a group's welcome is handed over, and each of them passes `-c relay:<file>` to `send`, `open`, `group new`, `group send`, `devices connect` and the rest. The file also holds the reader's cursor, so every copy is a separate reader of the same queue.

A queue is the one carrier that orders, so a group above `config::group::SMALL` members forms over it and over nothing else (L19).

## What the relay sees and cannot do

It sees bucket sizes, times, the network addresses of those who connect, how many readers collect from one queue, and that every blob in one queue is one conversation. It cannot read a blob, forge one that opens, produce a roster change, or tell one person's queue from another's. A relay that drops a blob is caught by the reader's cursor, since numbers are dense, and a relay that serves two readers different orders forks their group into a refusal that is seen and not repaired.

## Limits

A queue holds 1024 blobs and takes 600 puts a minute, a relay holds 100 000 queues, and a connection silent for two minutes is closed. Each is a constant in `crates/relay/src/lib.rs`. A blob above the largest bucket, or of a length that is not a bucket, is refused at the door.

## On disk

Under `--dir`: `cert.der`, `key.der` (mode 0600) and `queues/<id>/` holding `write` and `read`, the two capability hashes, and one file per blob named by its number. There is no index, no database and no log, and a copy of the directory is a copy of ciphertext every carrier already had.
