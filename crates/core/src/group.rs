//! Groups above two: `start`, `add`, `remove` and the roster everyone sees (L16 to L19).
//!
//! One member, the admin, holds the right to change the roster; every other member's client
//! refuses a roster change from anyone else. A member you never verified is shown as vouched
//! for by the admin and never as verified (L18). A roster larger than the small bound is
//! refused over a carrier that does not deliver in order (L19).

use crate::vocab::{MemberTrust, PeerState, Refuse};
use crate::{config, frame, mls_err, parse_key_package, prefix, Core, GroupRecord};
use openmls::prelude::*;
use serde::Serialize;
use unheld_blob::Blob;

/// One member of a group, as this vault sees them.
#[derive(Debug, Clone, Serialize)]
pub struct Member {
    /// A peer's name, or `?` and a key hash for someone you never verified.
    pub label: String,
    pub trust: MemberTrust,
    pub is_admin: bool,
    pub is_me: bool,
}

/// A group and its roster, with the verification state of every member (L18).
#[derive(Debug, Clone, Serialize)]
pub struct Roster {
    pub name: String,
    pub epoch: u64,
    pub admin: String,
    pub i_am_admin: bool,
    pub members: Vec<Member>,
}

/// The two blobs an `add` produces: a commit for the members, a welcome for the newcomer.
#[derive(Debug, Clone)]
pub struct Added {
    pub for_group: Blob,
    pub for_newcomer: Blob,
}

fn needs_order(members: usize, ordered: bool) -> Result<(), Refuse> {
    if members > config::group::SMALL && !ordered {
        return Err(Refuse::NeedsOrder(members, config::group::SMALL));
    }
    Ok(())
}

impl Core {
    /// How a signature key stands with you: your own name, a peer's name and state, or a
    /// vouched stranger shown by key hash.
    pub(crate) fn member_label(&self, key: &[u8]) -> (String, MemberTrust) {
        if let Ok(id) = self.identity() {
            if id.signature_public == key {
                return (id.name.clone(), MemberTrust::Verified);
            }
        }
        for (name, p) in &self.state.peers {
            if p.signature_public == key {
                let trust = match p.state {
                    PeerState::Verified => MemberTrust::Verified,
                    PeerState::Pending => MemberTrust::Pending,
                    PeerState::Changed => MemberTrust::Changed,
                };
                return (name.clone(), trust);
            }
        }
        (format!("{}{}", config::group::UNVERIFIED_PREFIX, prefix(key)), MemberTrust::Vouched)
    }

    fn group_record(&self, name: &str) -> Result<GroupRecord, Refuse> {
        self.state.groups.get(name).cloned().ok_or(Refuse::UnknownGroup)
    }

    fn load_group(&self, rec: &GroupRecord) -> Result<MlsGroup, Refuse> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&rec.group_id))
            .map_err(mls_err)?
            .ok_or(Refuse::UnknownGroup)
    }

    /// A verified peer's unused introduction, parsed. Refused for `Pending` or `Changed` (L3, L14).
    fn admitted_key_package(&self, name: &str) -> Result<KeyPackage, Refuse> {
        let rec = self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?;
        match rec.state {
            PeerState::Verified => {}
            PeerState::Changed => return Err(Refuse::Changed),
            PeerState::Pending => return Err(Refuse::Unverified),
        }
        let intro = rec.intro.as_ref().ok_or(Refuse::NoIntro)?;
        parse_key_package(&self.provider, intro)
    }

    fn consume_intro(&mut self, name: &str) {
        if let Some(r) = self.state.peers.get_mut(name) {
            r.intro = None;
        }
    }

    fn one_part_blob(msg: &MlsMessageOut) -> Result<Blob, Refuse> {
        let bytes = msg.to_bytes().map_err(mls_err)?;
        Blob::pad(&frame(&[bytes])?).map_err(|_| Refuse::TooLarge)
    }

    /// `start`: create a group with verified peers and become its admin. Returns the welcome
    /// every newcomer opens. `ordered` is what the carrier that will hold the group promises.
    pub fn group_new(&mut self, name: &str, peers: &[&str], ordered: bool) -> Result<Blob, Refuse> {
        if self.state.groups.contains_key(name) || self.state.peers.contains_key(name) {
            return Err(Refuse::GroupExists);
        }
        let members = peers.len() + 1;
        if members < config::group::MIN_MEMBERS {
            return Err(Refuse::TooSmall(config::group::MIN_MEMBERS));
        }
        needs_order(members, ordered)?;
        let kps = peers.iter().map(|p| self.admitted_key_package(p)).collect::<Result<Vec<_>, _>>()?;
        let signer = self.signer()?;
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(config::mls::CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config::mls::OUT_OF_ORDER_TOLERANCE,
                config::mls::MAX_FORWARD_DISTANCE,
            ))
            .build();
        let cwk = self.credential_with_key()?;
        let mut group = MlsGroup::new(&self.provider, &signer, &cfg, cwk).map_err(mls_err)?;
        let (_commit, welcome, _info) = group.add_members(&self.provider, &signer, &kps).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        let blob = Self::one_part_blob(&welcome)?;
        let admin = self.identity()?.signature_public.clone();
        self.state.groups.insert(
            name.to_owned(),
            GroupRecord { group_id: group.group_id().as_slice().to_vec(), admin },
        );
        for p in peers {
            self.consume_intro(p);
        }
        self.save()?;
        Ok(blob)
    }

    /// `add`: admit a verified peer. The commit goes to the members, the welcome to the newcomer.
    pub fn group_add(&mut self, name: &str, peer: &str, ordered: bool) -> Result<Added, Refuse> {
        let rec = self.group_record(name)?;
        if rec.admin != self.identity()?.signature_public {
            return Err(Refuse::NotAdmin);
        }
        let mut group = self.load_group(&rec)?;
        needs_order(group.members().count() + 1, ordered)?;
        let kp = self.admitted_key_package(peer)?;
        let signer = self.signer()?;
        let (commit, welcome, _info) = group
            .add_members(&self.provider, &signer, core::slice::from_ref(&kp))
            .map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        let added = Added { for_group: Self::one_part_blob(&commit)?, for_newcomer: Self::one_part_blob(&welcome)? };
        self.consume_intro(peer);
        self.save()?;
        Ok(added)
    }

    /// `remove`: drop a member by label. The commit goes to the members; the removed one opens
    /// nothing sealed afterwards (L17).
    pub fn group_remove(&mut self, name: &str, member: &str) -> Result<Blob, Refuse> {
        let rec = self.group_record(name)?;
        let me = self.identity()?.signature_public.clone();
        if rec.admin != me {
            return Err(Refuse::NotAdmin);
        }
        let mut group = self.load_group(&rec)?;
        let index = group
            .members()
            .find(|m| m.signature_key != me && self.member_label(&m.signature_key).0 == member)
            .map(|m| m.index)
            .ok_or(Refuse::NotMember)?;
        let signer = self.signer()?;
        let (commit, _welcome, _info) = group.remove_members(&self.provider, &signer, &[index]).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        let blob = Self::one_part_blob(&commit)?;
        self.save()?;
        Ok(blob)
    }

    /// `seal` to a group: one blob every member opens.
    pub fn group_seal(&mut self, name: &str, body: &[u8]) -> Result<Blob, Refuse> {
        let rec = self.group_record(name)?;
        let mut group = self.load_group(&rec)?;
        let signer = self.signer()?;
        let msg = group.create_message(&self.provider, &signer, body).map_err(mls_err)?;
        let blob = Self::one_part_blob(&msg)?;
        self.save()?;
        Ok(blob)
    }

    /// The roster with every member's verification state (L18).
    pub fn roster(&self, name: &str) -> Result<Roster, Refuse> {
        let rec = self.group_record(name)?;
        let group = self.load_group(&rec)?;
        let me = &self.identity()?.signature_public;
        let members = group
            .members()
            .map(|m| {
                let (label, trust) = self.member_label(&m.signature_key);
                Member { label, trust, is_admin: m.signature_key == rec.admin, is_me: &m.signature_key == me }
            })
            .collect();
        Ok(Roster {
            name: name.to_owned(),
            epoch: group.epoch().as_u64(),
            admin: self.member_label(&rec.admin).0,
            i_am_admin: &rec.admin == me,
            members,
        })
    }

    pub fn groups(&self) -> Vec<Roster> {
        self.state.groups.keys().filter_map(|n| self.roster(n).ok()).collect()
    }

    /// Give a group a different local name. Names never leave the vault.
    pub fn group_rename(&mut self, from: &str, to: &str) -> Result<(), Refuse> {
        if self.state.groups.contains_key(to) || self.state.peers.contains_key(to) {
            return Err(Refuse::GroupExists);
        }
        let rec = self.state.groups.remove(from).ok_or(Refuse::UnknownGroup)?;
        self.state.groups.insert(to.to_owned(), rec);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-group-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Two vaults that have verified each other.
    fn pair(a: &mut Core, a_name: &str, b: &mut Core, b_name: &str) {
        a.import(b_name, &b.intro().unwrap()).unwrap();
        a.verify(b_name, true).unwrap();
        b.import(a_name, &a.intro().unwrap()).unwrap();
        b.verify(a_name, true).unwrap();
    }

    fn joined_name(core: &Core) -> String {
        core.groups().into_iter().next().unwrap().name
    }

    #[test]
    fn a_group_of_three_and_its_laws() {
        let mut alice = Core::create(&tmp("g-alice"), "pw", "alice").unwrap();
        let mut bob = Core::create(&tmp("g-bob"), "pw", "bob").unwrap();
        let mut carol = Core::create(&tmp("g-carol"), "pw", "carol").unwrap();
        let mut dave = Core::create(&tmp("g-dave"), "pw", "dave").unwrap();
        // Alice has met everyone; Bob, Carol and Dave have met only Alice.
        pair(&mut alice, "alice", &mut bob, "bob");
        pair(&mut alice, "alice", &mut carol, "carol");
        pair(&mut alice, "alice", &mut dave, "dave");

        // Two people is a session, not a group.
        assert!(matches!(alice.group_new("team", &["bob"], false), Err(Refuse::TooSmall(_))));
        let welcome = alice.group_new("team", &["bob", "carol"], false).unwrap();
        let joined = bob.open(&welcome).unwrap();
        assert!(joined[0].session_started && joined[0].from == "alice");
        carol.open(&welcome).unwrap();
        let bob_team = joined_name(&bob);

        // L18: Bob sees Alice verified and Carol vouched, never verified.
        let roster = bob.roster(&bob_team).unwrap();
        assert_eq!(roster.admin, "alice");
        assert!(!roster.i_am_admin);
        let trusts: Vec<MemberTrust> = roster.members.iter().filter(|m| !m.is_me).map(|m| m.trust).collect();
        assert!(trusts.contains(&MemberTrust::Verified) && trusts.contains(&MemberTrust::Vouched));

        // Messages flow; a vouched sender is shown as such with the admin's name.
        let hello = alice.group_seal("team", b"hello team").unwrap();
        let got = bob.open(&hello).unwrap();
        assert_eq!((got[0].from.as_str(), &got[0].body[..]), ("alice", &b"hello team"[..]));
        assert_eq!(carol.open(&hello).unwrap()[0].body, b"hello team");
        let carol_team = joined_name(&carol);
        let from_carol = carol.group_seal(&carol_team, b"hi from carol").unwrap();
        let got = bob.open(&from_carol).unwrap();
        assert_eq!(got[0].trust, MemberTrust::Vouched);
        assert_eq!(got[0].vouched_by.as_deref(), Some("alice"));
        assert!(got[0].from.starts_with(config::group::UNVERIFIED_PREFIX));
        assert_eq!(alice.open(&from_carol).unwrap()[0].from, "carol");

        // Only the admin adds (L16, locally).
        assert!(matches!(bob.group_add(&bob_team, "alice", false), Err(Refuse::NotAdmin)));
        let added = alice.group_add("team", "dave", false).unwrap();
        let seen = bob.open(&added.for_group).unwrap();
        assert!(seen[0].change.as_deref().unwrap().contains("added"));
        carol.open(&added.for_group).unwrap();
        // L17: the newcomer opens nothing sealed before joining.
        assert!(matches!(dave.open(&hello), Err(Refuse::UnknownSession)));
        dave.open(&added.for_newcomer).unwrap();
        let dave_team = joined_name(&dave);
        assert_eq!(dave.roster(&dave_team).unwrap().members.len(), 4);
        let after = alice.group_seal("team", b"four now").unwrap();
        assert_eq!(dave.open(&after).unwrap()[0].body, b"four now");
        bob.open(&after).unwrap();
        carol.open(&after).unwrap();

        // Removal: the roster change is shown to all, and the removed member is out (L16, L17).
        let carol_label = alice.roster("team").unwrap().members.iter().find(|m| m.label == "carol").unwrap().label.clone();
        let removal = alice.group_remove("team", &carol_label).unwrap();
        let seen = bob.open(&removal).unwrap();
        assert!(seen[0].change.as_deref().unwrap().contains("removed"));
        dave.open(&removal).unwrap();
        let seen = carol.open(&removal).unwrap();
        assert!(seen[0].change.as_deref().unwrap().contains("removed you"));
        assert!(carol.groups().is_empty());
        let later = alice.group_seal("team", b"without carol").unwrap();
        assert!(matches!(carol.open(&later), Err(Refuse::UnknownSession)));
        assert_eq!(bob.open(&later).unwrap()[0].body, b"without carol");
        assert_eq!(alice.roster("team").unwrap().members.len(), 3);
    }

    #[test]
    fn a_roster_change_from_a_non_admin_is_refused_by_every_member() {
        let mut alice = Core::create(&tmp("r-alice"), "pw", "alice").unwrap();
        let mut bob = Core::create(&tmp("r-bob"), "pw", "bob").unwrap();
        let mut carol = Core::create(&tmp("r-carol"), "pw", "carol").unwrap();
        let mut eve = Core::create(&tmp("r-eve"), "pw", "eve").unwrap();
        pair(&mut alice, "alice", &mut bob, "bob");
        pair(&mut alice, "alice", &mut carol, "carol");
        pair(&mut bob, "bob", &mut eve, "eve");
        let welcome = alice.group_new("team", &["bob", "carol"], false).unwrap();
        bob.open(&welcome).unwrap();
        carol.open(&welcome).unwrap();
        // Bob's client is altered so it believes Bob is the admin, and it adds Eve.
        let bob_team = joined_name(&bob);
        bob.state.groups.get_mut(&bob_team).unwrap().admin = bob.identity().unwrap().signature_public.clone();
        let ghost = bob.group_add(&bob_team, "eve", false).unwrap();
        // Alice and Carol refuse the commit and their group does not move (L16).
        assert!(matches!(alice.open(&ghost.for_group), Err(Refuse::NoRight)));
        assert!(matches!(carol.open(&ghost.for_group), Err(Refuse::NoRight)));
        assert_eq!(alice.roster("team").unwrap().members.len(), 3);
        let msg = alice.group_seal("team", b"still three").unwrap();
        assert_eq!(carol.open(&msg).unwrap()[0].body, b"still three");
        // A pairwise session accepts no roster change at all.
        let mut dan = Core::create(&tmp("r-dan"), "pw", "dan").unwrap();
        pair(&mut alice, "alice", &mut dan, "dan");
        let first = alice.seal("dan", b"one").unwrap();
        dan.open(&first).unwrap();
        assert_eq!(dan.groups().len(), 0);
    }

    #[test]
    fn a_large_group_needs_an_ordered_carrier() {
        let mut alice = Core::create(&tmp("big"), "pw", "alice").unwrap();
        let names: Vec<String> = (0..config::group::SMALL).map(|i| format!("p{i}")).collect();
        let peers: Vec<&str> = names.iter().map(String::as_str).collect();
        // One above the bound over an unordered carrier is refused before any key is touched (L19).
        assert!(matches!(alice.group_new("big", &peers, false), Err(Refuse::NeedsOrder(n, b)) if n == config::group::SMALL + 1 && b == config::group::SMALL));
        // The same roster over an ordered carrier passes the bound and fails only on the unknown names.
        assert!(matches!(alice.group_new("big", &peers, true), Err(Refuse::UnknownPeer)));
        // At the bound an unordered carrier is fine.
        let at_bound: Vec<&str> = peers.iter().copied().take(config::group::SMALL - 1).collect();
        assert!(matches!(alice.group_new("big", &at_bound, false), Err(Refuse::UnknownPeer)));
    }
}
