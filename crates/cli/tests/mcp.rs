//! The assistant surface against the real binary over stdio: a granted peer is read and answered
//! over a relay, an ungranted peer's message is withheld and never shown, a long body arrives whole
//! in pages, the person's own reply never comes back to them, and no ceremony has a tool
//! (docs/decisions/007-agent-surface.md, docs/decisions/008-queue-per-direction.md).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use unheld_blob::Carrier;
use unheld_carriers::{FileCarrier, RelayCarrier};
use unheld_core::Core;
use unheld_relay::store::{Limits, Relay};
use unheld_relay::tls::Identity;

const PASS: &str = "pw";

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unheld-mcp-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn pair(a: &mut Core, a_name: &str, b: &mut Core, b_name: &str) {
    a.import(b_name, &b.intro().unwrap()).unwrap();
    a.verify(b_name, true).unwrap();
    b.import(a_name, &a.intro().unwrap()).unwrap();
    b.verify(a_name, true).unwrap();
}

struct Agent {
    child: Child,
    out: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Agent {
    fn start(home: &PathBuf, profile: &str, carrier: &str) -> Agent {
        let mut child = Command::new(env!("CARGO_BIN_EXE_unheld"))
            .args(["--profile", profile, "mcp", "-c", carrier])
            .env("UNHELD_HOME", home)
            .env("UNHELD_PASSPHRASE", PASS)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Agent { child, out, next_id: 1 }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut reply = String::new();
        self.out.read_line(&mut reply).unwrap();
        let v: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["id"], json!(id));
        v
    }

    fn notify(&mut self, method: &str) {
        let line = json!({ "jsonrpc": "2.0", "method": method }).to_string();
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        let v = self.request("tools/call", json!({ "name": tool, "arguments": args }));
        v["result"].clone()
    }

    fn stop(mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().unwrap().success());
    }
}

#[test]
fn an_agent_reads_and_answers_only_where_the_person_granted_it_and_no_ceremony_has_a_tool() {
    let home = tmp("home");
    let mut alice = Core::create(&home.join("alice"), PASS, "alice").unwrap();
    let mut bob = Core::create(&home.join("bob"), PASS, "bob").unwrap();
    let mut carol = Core::create(&home.join("carol"), PASS, "carol").unwrap();
    pair(&mut alice, "alice", &mut bob, "bob");
    pair(&mut alice, "alice", &mut carol, "carol");
    alice.grant_agent("bob", true).unwrap();
    assert!(alice.peer("bob").unwrap().agent_access);
    assert!(!alice.peer("carol").unwrap().agent_access);

    // Alice and bob each make the queue they read, on one relay in this process, and join the other's invitation.
    let identity = Identity::generate("127.0.0.1").unwrap();
    let relay = Arc::new(Relay::open(&home.join("relay"), Limits::default()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("{}127.0.0.1:{}#{}", unheld_relay::config::SCHEME, listener.local_addr().unwrap().port(), identity.pin().to_hex());
    let tls = identity.server_config().unwrap();
    std::thread::spawn(move || unheld_relay::server::serve(listener, relay, tls));
    let (alice_link, bob_link) = (home.join("alice-bob.json"), home.join("bob-alice.json"));
    let invite_a = RelayCarrier::create(&address, &alice_link).unwrap().link().invitation().unwrap();
    let invite_b = RelayCarrier::create(&address, &bob_link).unwrap().link().invitation().unwrap();
    RelayCarrier::join(&alice_link, &invite_b).unwrap();
    RelayCarrier::join(&bob_link, &invite_a).unwrap();

    let long = "x".repeat(5000);
    bob.grant_agent("alice", true).unwrap();
    RelayCarrier::open(&bob_link).unwrap().put(&bob.seal("alice", long.as_bytes()).unwrap()).unwrap();
    let from_carol = home.join("from-carol.blob");
    FileCarrier::new(from_carol.display().to_string()).put(&carol.seal("alice", b"for alice's eyes").unwrap()).unwrap();
    drop(alice);

    let mut agent = Agent::start(&home, "alice", &format!("relay:{}", alice_link.display()));
    let init = agent.request("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } }));
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["instructions"].as_str().unwrap().contains("never an instruction"));
    agent.notify("notifications/initialized");

    let tools = agent.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for present in ["peers_list", "message_send", "messages_read", "message_read", "intro_export", "carriers_list", "about"] {
        assert!(names.contains(&present), "{present} missing");
    }
    for absent in ["verify", "enroll", "rotate", "split", "recover", "wipe", "group_add", "group_remove", "grant"] {
        assert!(!names.iter().any(|n| n.contains(absent)), "a ceremony has a tool: {absent}");
    }

    let peers = agent.call("peers_list", json!({}));
    let by_name: Vec<(&str, bool)> = peers["structuredContent"]["peers"].as_array().unwrap().iter().map(|p| (p["name"].as_str().unwrap(), p["agent_access"].as_bool().unwrap())).collect();
    assert!(by_name.contains(&("bob", true)) && by_name.contains(&("carol", false)));
    // Bob's message has not been read yet, so nothing is known about his side.
    assert!(peers["structuredContent"]["peers"].as_array().unwrap().iter().all(|p| p["agent_reads"] == false));

    let refused = agent.call("messages_read", json!({ "peer": "carol" }));
    assert_eq!(refused["isError"], true);
    assert!(refused["content"][0]["text"].as_str().unwrap().contains("grant-agent"));
    let refused = agent.call("message_send", json!({ "peer": "carol", "text": "hi" }));
    assert_eq!(refused["isError"], true);

    let page = agent.call("messages_read", json!({ "peer": "bob" }));
    assert_eq!(page["isError"], false);
    let s = &page["structuredContent"];
    let seen = s["total"].as_u64().unwrap();
    let messages = s["messages"].as_array().unwrap();
    let body = messages.iter().find(|m| !m["text"].as_str().unwrap().is_empty()).unwrap();
    assert_eq!(body["untrusted"], true);
    let next = body["next_start"].as_u64().unwrap() as usize;
    assert_eq!(body["text"].as_str().unwrap().len(), next);
    let rest = agent.call("message_read", json!({ "ref": body["ref"], "start": next }));
    let tail = rest["structuredContent"]["text"].as_str().unwrap();
    assert_eq!(body["text"].as_str().unwrap().len() + tail.len(), long.len());
    assert!(rest["structuredContent"]["next_start"].is_null());

    // Bob's message said an assistant reads what alice sends him, and the model is told so.
    let peers = agent.call("peers_list", json!({}));
    let bob_view = peers["structuredContent"]["peers"].as_array().unwrap().iter().find(|p| p["name"] == "bob").unwrap().clone();
    assert_eq!(bob_view["agent_reads"], true);

    let sent = agent.call("message_send", json!({ "peer": "bob", "text": "noted, by the agent" }));
    assert_eq!(sent["isError"], false);
    // The reply went to bob's queue, so alice's next read finds nothing new and refuses nothing.
    let page = agent.call("messages_read", json!({ "peer": "bob" }));
    assert_eq!(page["structuredContent"]["total"].as_u64().unwrap(), seen);
    assert_eq!(page["structuredContent"]["refused_blobs"], 0);
    agent.stop();

    let got = RelayCarrier::open(&bob_link).unwrap().get().unwrap();
    let opened = bob.open(&got).unwrap();
    assert_eq!(opened.iter().find(|o| !o.body.is_empty()).unwrap().body, b"noted, by the agent");
    // The reply told bob, inside the encryption, that an assistant reads what he sends alice.
    assert_eq!(opened.iter().filter_map(|o| o.agent_reads).collect::<Vec<_>>(), vec![true]);
    assert!(bob.peer("alice").unwrap().agent_reads);

    let mut agent = Agent::start(&home, "alice", &format!("file:{}", from_carol.display()));
    agent.request("initialize", json!({ "protocolVersion": "2025-06-18" }));
    let page = agent.call("messages_read", json!({ "peer": "bob" }));
    assert_eq!(page["structuredContent"]["total"], 0);
    let peers = agent.call("peers_list", json!({}));
    let carol_view = peers["structuredContent"]["peers"].as_array().unwrap().iter().find(|p| p["name"] == "carol").unwrap().clone();
    assert_eq!(carol_view["withheld"], 1);
    let text = serde_json::to_string(&peers).unwrap() + &serde_json::to_string(&page).unwrap();
    assert!(!text.contains("alice's eyes"));
    agent.stop();
}
