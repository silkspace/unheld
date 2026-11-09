"""The laws, from the Python side, with a list as the carrier."""

from pathlib import Path

import pytest

import unheld

PASS = "correct horse battery staple"


def person(tmp: Path, name: str) -> unheld.Core:
    return unheld.Core.create(tmp / name, PASS, name)


def meet(a: unheld.Core, b: unheld.Core) -> None:
    """Both import, both read the same digits, both say yes."""
    a.import_intro(b.name, b.intro())
    b.import_intro(a.name, a.intro())
    assert a.fingerprint(b.name) == b.fingerprint(a.name)
    a.verify(b.name, confirmed=True)
    b.verify(a.name, confirmed=True)


def test_verify_is_the_only_constructor_and_a_blob_opens_once(tmp_path: Path) -> None:
    alice = person(tmp_path, "alice")
    bob = person(tmp_path, "bob")
    alice.import_intro("bob", bob.intro())
    bob.import_intro("alice", alice.intro())

    assert alice.peer("bob").state is unheld.PeerState.Pending
    with pytest.raises(unheld.Refused) as refused:
        alice.seal("bob", b"too soon")
    assert refused.value.reason is unheld.Refuse.Unverified

    with pytest.raises(unheld.Refused) as refused:
        alice.verify("bob", confirmed=False)
    assert refused.value.reason is unheld.Refuse.NotConfirmed
    assert alice.peer("bob").state is unheld.PeerState.Pending

    assert alice.fingerprint("bob") == bob.fingerprint("alice")
    assert alice.verify("bob", confirmed=True).state is unheld.PeerState.Verified
    bob.verify("alice", confirmed=True)
    assert not alice.peer("bob").agent_access
    assert alice.grant_agent("bob", True).agent_access
    assert not alice.grant_agent("bob", False).agent_access

    blob = alice.seal("bob", b"hello from python")
    assert len(blob) in unheld.BUCKETS
    outside = unheld.inspect(blob)
    assert outside.bucket == len(blob)
    assert all(p.kind in (unheld.Part.Welcome, unheld.Part.Message, unheld.Part.Opaque) for p in outside.parts)

    opened = bob.open(blob)
    assert opened[0].session_started and opened[0].body == b""
    assert [o.body for o in opened if o.body] == [b"hello from python"]
    assert all(o.moved_to is None and o.agent_reads is None for o in opened)
    assert not bob.peer("alice").agent_reads
    assert {o.sender for o in opened} == {"alice"}
    assert {o.trust for o in opened} == {unheld.MemberTrust.Verified}

    with pytest.raises(unheld.Refused) as refused:
        bob.open(blob)
    assert refused.value.reason is unheld.Refuse.Replay

    with pytest.raises(unheld.Refused) as refused:
        bob.open(b"not a bucket")
    assert refused.value.reason is unheld.Refuse.BadBlob


def test_the_vault_persists_what_each_verb_wrote(tmp_path: Path) -> None:
    alice = person(tmp_path, "alice")
    bob = person(tmp_path, "bob")
    meet(alice, bob)
    blob = alice.seal("bob", b"before the lock")
    del alice, bob

    with pytest.raises(unheld.Refused) as refused:
        unheld.Core.unlock(tmp_path / "bob", "wrong")
    assert refused.value.reason is unheld.Refuse.VaultLocked

    bob = unheld.Core.unlock(tmp_path / "bob", PASS)
    assert bob.peer("alice").state is unheld.PeerState.Verified
    assert [o.body for o in bob.open(blob) if o.body] == [b"before the lock"]

    alice = unheld.Core.unlock(tmp_path / "alice", PASS)
    moved = alice.seal("bob", b"and my queue moved", moved_to="wherever the program's transport says")
    assert [(o.body, o.moved_to) for o in bob.open(moved)] == [(b"and my queue moved", "wherever the program's transport says")]

    alice.grant_agent("bob", True)
    told = bob.open(alice.seal("bob", b"and an assistant reads your replies"))
    assert [o.agent_reads for o in told] == [True]
    assert bob.peer("alice").agent_reads
    assert [o.agent_reads for o in bob.open(alice.seal("bob", b"still does"))] == [None]

    unheld.wipe(tmp_path / "bob")
    with pytest.raises(unheld.Refused) as refused:
        unheld.Core.unlock(tmp_path / "bob", PASS)
    assert refused.value.reason is unheld.Refuse.NoVault


def test_a_group_over_a_list_shows_every_roster_change(tmp_path: Path) -> None:
    alice = person(tmp_path, "alice")
    bob = person(tmp_path, "bob")
    carol = person(tmp_path, "carol")
    meet(alice, bob)
    meet(alice, carol)

    with pytest.raises(unheld.Refused) as refused:
        alice.group_new("team", ["bob"], ordered=False)
    assert refused.value.reason is unheld.Refuse.TooSmall

    queue: list[bytes] = [alice.group_new("team", ["bob", "carol"], ordered=False)]
    for member in (bob, carol):
        opened = member.open(queue[0])
        assert opened[0].group is not None
        assert opened[0].change is not None
    bob_group = next(r for r in bob.groups()).name

    queue.append(alice.group_seal("team", b"to both of you"))
    for member in (bob, carol):
        assert [o.body for o in member.open(queue[1])] == [b"to both of you"]

    roster = bob.roster(bob_group)
    assert roster.admin == "alice" and not roster.i_am_admin
    by_trust = {m.trust: m for m in roster.members if not m.is_me}
    assert by_trust[unheld.MemberTrust.Verified].label == "alice"
    assert by_trust[unheld.MemberTrust.Verified].is_admin
    assert not by_trust[unheld.MemberTrust.Vouched].is_admin

    with pytest.raises(unheld.Refused) as refused:
        bob.group_remove(bob_group, "carol")
    assert refused.value.reason is unheld.Refuse.NotAdmin

    queue.append(alice.group_remove("team", "carol"))
    removed = carol.open(queue[2])
    assert removed[0].change is not None
    kept = bob.open(queue[2])
    assert kept[0].change is not None
    assert all(m.trust is not unheld.MemberTrust.Vouched for m in bob.roster(bob_group).members)

    queue.append(alice.group_seal("team", b"after the removal"))
    assert [o.body for o in bob.open(queue[3])] == [b"after the removal"]
    with pytest.raises(unheld.Refused):
        carol.open(queue[3])


def test_shares_rebuild_the_identity_and_a_bad_share_rebuilds_nothing(tmp_path: Path) -> None:
    alice = person(tmp_path, "alice")
    shares = alice.split(2, 3)
    assert [s.index for s in shares] == [1, 2, 3]
    assert all(s.threshold == 2 for s in shares)
    texts = [s.to_text() for s in shares]

    with pytest.raises(unheld.Refused) as refused:
        unheld.Core.recover(tmp_path / "again", PASS, "alice", [unheld.Share.from_text(texts[0])])
    assert refused.value.reason is unheld.Refuse.NotEnoughShares

    again = unheld.Core.recover(tmp_path / "again", PASS, "alice", [unheld.Share.from_text(t) for t in texts[1:]])
    assert again.fingerprint_prefix == alice.fingerprint_prefix
    assert again.peers() == []
