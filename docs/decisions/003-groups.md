# 003: groups above two without a server

**Status.** Accepted for the overlay; revisited when the ordered relay exists.

**Laws touched.** L16 (no ghost), L17 (membership secrecy), L18 (vouch is not verify), L19 (ordered or small).

## The question

Messaging Layer Security gives a group one tree, one epoch and a total order on commits, and it assumes a delivery service that supplies that order and says nothing about who may change the roster. The overlay has carriers that supply no order at all and a kernel that says a roster changes only by a commit from a verified member with policy rights. The question is what policy, and what a member who joined through someone else's welcome knows and is told.

## The decision

**One admin, and it is the creator.** A group's roster is changed only by commits from the member who started it. Every other client checks the signer of any commit that adds or removes against the admin key it recorded at join and refuses otherwise, before merging, so a refused commit moves nothing. This is the smallest policy that satisfies L16 and it is what a joiner can check without any further ceremony, because the admin is the one whose welcome they opened, and a welcome is accepted only from a peer they verified themselves. Commits that change no roster, such as a member refreshing their own keys, are accepted from any member. A pairwise session accepts no roster change at all, so nobody turns a conversation into a group from the outside.

**A joiner knows the admin and nobody else.** The admin has verified everyone they put in the roster; the others have verified the admin and perhaps some of each other. A member whose key matches no peer in your vault is shown as `Vouched`, with the admin's name and the hash of their key, and never as `Verified`. Verifying them yourself later, by importing their introduction and comparing digits, turns the label into their name. `group send` prints every reader with their state before sealing, so the fact that your words reach someone you never met is in front of you each time (L18).

**Two blobs for an add.** The commit that admits a newcomer is for the members and the welcome is for the newcomer, and they are written to two carriers, because a blob is opened whole or refused whole (L8) and one blob that is half for one party and half for another would force a client to skip a part that failed.

**Ordered or small.** With no ordered carrier, two commits that cross in transit fork the group, and MLS has no merge. Above `config::group::SMALL` members a group is refused on any carrier that does not promise order, with the bound in the refusal. Below it the risk is accepted and bounded by the single-admin rule, since only one party ever commits roster changes, and the remaining race is that admin issuing two commits before anyone opened the first.

**Names stay local.** A joiner's group is named from the session hash until renamed, because names never leave the vault, and a group name chosen by the admin would travel in the clear or in a message the kernel does not have.

## What is not here

Leaving is deleting your own keys; the others list you until the admin removes you, since a leave proposal needs a committer and the committer is the admin. The admin cannot leave or hand over. Self-updates for post-compromise security are not yet sent on a schedule. All three are the next steps on this surface, after the relay gives large groups an order.
