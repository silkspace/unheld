//! L19 over the first ordered carrier: a group above the small bound forms over the relay, and a
//! relay that orders differently for different readers forks the group into a refusal that is
//! seen and not repaired (docs/decisions/006-relay.md).

use std::path::PathBuf;
use std::sync::Arc;
use unheld_blob::Carrier;
use unheld_core::{config, vocab::Refuse, Core};
use unheld_relay::carrier::{Adversary, LocalTransport, Queue, RelayCarrier};
use unheld_relay::store::{Limits, Relay};
use unheld_relay::tls::Pin;

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unheld-relay-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn pair(a: &mut Core, a_name: &str, b: &mut Core, b_name: &str) {
    a.import(b_name, &b.intro().unwrap()).unwrap();
    a.verify(b_name, true).unwrap();
    b.import(a_name, &a.intro().unwrap()).unwrap();
    b.verify(a_name, true).unwrap();
}

#[test]
fn a_group_above_the_bound_forms_over_the_relay_and_an_equivocating_relay_forks_it() {
    let bound = config::group::SMALL;
    let mut alice = Core::create(&tmp("alice"), "pw", "alice").unwrap();
    let names: Vec<String> = (1..=bound).map(|i| format!("m{i}")).collect();
    let mut members: Vec<Core> = names.iter().map(|m| Core::create(&tmp(m), "pw", m).unwrap()).collect();
    for (m, name) in members.iter_mut().zip(&names) {
        pair(&mut alice, "alice", m, name);
    }
    let peers: Vec<&str> = names.iter().map(String::as_str).collect();

    let relay = Arc::new(Relay::open(&tmp("store"), Limits::default()).unwrap());
    let mut admin = RelayCarrier::create_on(LocalTransport::new(Arc::clone(&relay)), "local", Pin([0; 32])).unwrap();
    let queue = admin.queue().clone();
    let reader = |after: u64, adversary: Adversary| {
        RelayCarrier::new(Queue { after, ..queue.clone() }, LocalTransport::hostile(Arc::clone(&relay), adversary), None)
    };

    // One above the bound is refused over a carrier that does not order, and passes over one that does.
    assert!(matches!(alice.group_new("big", &peers, false), Err(Refuse::NeedsOrder(n, b)) if n == bound + 1 && b == bound));
    let welcome = alice.group_new("big", &peers, admin.ordered()).unwrap();
    admin.put(&welcome).unwrap();
    let mut readers: Vec<_> = members.iter().map(|_| reader(0, Adversary::default())).collect();
    for (m, q) in members.iter_mut().zip(readers.iter_mut()) {
        let joined = m.open(&q.get().unwrap()).unwrap();
        assert!(joined[0].session_started && joined[0].from == "alice");
    }
    admin.put(&alice.group_seal("big", b"nine of us").unwrap()).unwrap();
    for (m, q) in members.iter_mut().zip(readers.iter_mut()) {
        assert_eq!(m.open(&q.get().unwrap()).unwrap()[0].body, b"nine of us");
    }

    // Two roster changes in a row take positions 3 and 4 in the relay's order; a message in the
    // epoch after both takes 5.
    let label = |core: &Core, who: &str| core.roster("big").unwrap().members.iter().find(|m| m.label == who).unwrap().label.clone();
    let last = names.last().unwrap().clone();
    let second_last = names[names.len() - 2].clone();
    admin.put(&alice.group_remove("big", &label(&alice, &last)).unwrap()).unwrap();
    admin.put(&alice.group_remove("big", &label(&alice, &second_last)).unwrap()).unwrap();
    admin.put(&alice.group_seal("big", b"seven of us").unwrap()).unwrap();

    // An honest reader applies both and opens what follows.
    let honest = &mut members[0];
    let q = &mut readers[0];
    assert!(honest.open(&q.get().unwrap()).unwrap()[0].change.as_deref().unwrap().contains("removed"));
    assert!(honest.open(&q.get().unwrap()).unwrap()[0].change.as_deref().unwrap().contains("removed"));
    assert_eq!(honest.open(&q.get().unwrap()).unwrap()[0].body, b"seven of us");

    // A reader whose relay serves the two commits the other way round refuses the one that
    // arrives first, applies the other, and is then out of step with the group for good.
    let forked = &mut members[1];
    let mut q = reader(2, Adversary { swap: vec![(3, 4)], ..Adversary::default() });
    assert!(matches!(forked.open(&q.get().unwrap()), Err(Refuse::Replay | Refuse::Protocol)));
    assert!(forked.open(&q.get().unwrap()).unwrap()[0].change.as_deref().unwrap().contains("removed"));
    assert!(forked.open(&q.get().unwrap()).is_err());

    // The removed member sees the removal and opens nothing sealed after it (L17).
    let removed = members.last_mut().unwrap();
    let q = readers.last_mut().unwrap();
    assert!(removed.open(&q.get().unwrap()).unwrap()[0].change.as_deref().unwrap().contains("removed"));
    assert!(removed.open(&q.get().unwrap()).is_err());
}
