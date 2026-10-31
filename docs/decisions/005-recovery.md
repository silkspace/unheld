# 005: recovery rebuilds the key and nothing else

**Status.** Accepted for the overlay.

**Laws touched.** L21 (shares by ceremony), L2 (zero custody), L3 (no skip).

## The question

A lost device takes the vault with it, and the kernel's answer is `split`, which cuts `Id` into `n` Shamir shares of which any `k` rebuild it, under a ceremony and never by `lock`. The questions are what exactly is in a share, what a person holds after `join`, and how a share can be shown without being kept.

## The decision

**The identity key alone.** A share is a Shamir share, over the field of 256 elements and one polynomial per byte, of the identity signing key pair, and of nothing else. Peers, sessions, groups and the device list are the vault's and die with it. What survives is the one thing a peer verified, so a recovered identity's introduction is accepted by every peer who compared digits with the old one as the same `Verified` person, and the recovered side runs the ceremony again for each of them, since its own peer list is gone. A share says which of `n` it is and how many are needed, and says nothing about whose identity it is.

**A ceremony, not a file.** `recover split` reads the vault, cuts the key, shows each share once with the screen cleared between them, and writes nothing: the vault file is byte for byte what it was, and the test pins that. `Share` has one constructor, `split`, and zeroises when it drops. The person decides where each share goes and the client does not know, which is also why the graph of who holds your shares is not the client's to leak, though the ceremony itself is (TRACE.md).

**A wrong share is a refusal.** Shamir rebuilds something from any `k` shares, right or wrong, so `join` signs a fixed message with the rebuilt key and checks it under the rebuilt public key before any vault is written. An altered share therefore produces a refusal and no vault, not a vault with a key nobody has.

**Threshold at least two.** A split with `k = 1` would be `n` copies of the key and is refused.

## What is not here

The ring and the device list do not survive recovery; a recovered identity is one device until others are enrolled again. Shares are text to copy; a wordlist encoding and a QR form are display choices for the shells. Verifiable shares, which would let a holder check theirs without the others, are available in the same crate and not used, because a share is handed over in person and checked at `join`. Whether a recovery that does not reveal the share holders to an observer of the ceremony exists is open.
