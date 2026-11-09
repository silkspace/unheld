#![forbid(unsafe_code)]
//! The command-line client. Each subcommand is one kernel verb; every refusal is exit code 2.

use clap::{Parser, Subcommand};
use owo_colors::{OwoColorize, Stream};
use unheld_core::vocab::{MemberTrust, PeerState};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use unheld_blob::{Blob, Carrier};
use unheld_carriers::{ClipboardCarrier, FileCarrier, RelayCarrier, StdioCarrier};
use unheld_core::config;
use unheld_core::vocab::Refuse;
use unheld_core::{Attach, Core, Enrolment, Intro, Outbound, Request, Share};

mod mcp;

#[derive(Parser)]
#[command(name = "unheld", about = "Messaging where nobody but the two of you holds a key.")]
struct Cli {
    /// Profile name; each profile is one vault under the unheld home directory.
    #[arg(long, default_value = "default")]
    profile: String,
    /// Emit typed JSON instead of prose.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Identity: create or show.
    Id {
        #[command(subcommand)]
        cmd: IdCmd,
    },
    /// Introductions: export yours, import theirs.
    Intro {
        #[command(subcommand)]
        cmd: IntroCmd,
    },
    /// Compare the pairwise safety number with a peer and confirm it.
    Verify {
        name: String,
        /// Also draw the number as a QR code; scanning it fills the comparison and never replaces it.
        #[arg(long)]
        qr: bool,
    },
    /// List peers and their verification state, or change what an agent may do with one.
    Peers {
        #[command(subcommand)]
        cmd: Option<PeersCmd>,
    },
    /// Encrypt a message (from stdin) to a verified peer and hand the blob to a carrier.
    Send {
        name: String,
        /// Carrier: `stdout`, `clipboard`, `file:<path>` or `relay:<link file>`.
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Take a blob from a carrier and decrypt it.
    Open {
        /// Carrier: `stdin`, `clipboard`, `file:<path>` or `relay:<link file>`.
        #[arg(short, long, default_value = "stdin")]
        carrier: String,
    },
    /// Groups above two: start one, add, remove, send, and see every member's state.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Devices of one identity: enrol a new one with a witness, bring it into every session, revoke.
    Devices {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Recovery shares: split the identity key into n shares of which any k rebuild it, or rebuild it.
    Recover {
        #[command(subcommand)]
        cmd: RecoverCmd,
    },
    /// End every session with a peer, or leave a group, and delete the keys; a peer stays verified.
    Forget { name: String },
    /// Set a duress passphrase: unlocking with it destroys the vault and answers as a wrong passphrase would.
    Duress,
    /// Destroy this profile's vault now.
    Wipe,
    /// Read a blob the way a carrier would, with no vault and no key, and print what it learns.
    Inspect {
        /// Carrier: `stdin` or `file:<path>`.
        #[arg(short, long, default_value = "stdin")]
        carrier: String,
    },
    /// This build and what is known about it.
    About,
    /// Serve the client to an assistant over stdio as a Model Context Protocol server (docs/MCP.md).
    Mcp {
        /// Carrier the agent reads and sends through: `file:<path>`, `clipboard` or `relay:<link file>`.
        #[arg(short, long)]
        carrier: String,
    },
    /// Queues on a relay: the one carrier that orders. One queue per direction between two people, one shared queue for a group.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
}

#[derive(Subcommand)]
enum PeersCmd {
    /// Let an agent read and send with this peer through `unheld mcp`. Your decision, made here and nowhere else.
    GrantAgent { name: String },
    /// Stop an agent reading or sending with this peer.
    RevokeAgent { name: String },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Make your queue on the relay at `address` (as `unheld-relay init` printed it), write its file,
    /// and print the invitation the other person joins. For a group, hand the file itself to every member.
    New { address: String, file: String },
    /// Point `file` at the other person's queue with the invitation they handed you; after both have joined, each reads only what the other wrote.
    Join { file: String, invitation: String },
}

#[derive(Subcommand)]
enum IdCmd {
    New { name: String },
    Show,
    /// New identity keys. Every peer sees `Changed` with your next message and must verify again;
    /// your other devices take the new key from the ring blob written here.
    Rotate {
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Start a group with verified peers; you become its admin. The welcome goes to every peer named.
    New {
        name: String,
        #[arg(required = true, num_args = 2..)]
        peers: Vec<String>,
        /// Carrier for the welcome: `stdout`, `clipboard`, `file:<path>` or `relay:<link file>`.
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Admit a verified peer. The commit goes to the members, the welcome to the newcomer.
    Add {
        group: String,
        peer: String,
        /// Carrier for the commit the members open.
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
        /// Carrier for the welcome the newcomer opens.
        #[arg(short, long, default_value = "stdout")]
        welcome: String,
    },
    /// Remove a member by the label `roster` shows. The commit goes to the members.
    Remove {
        group: String,
        member: String,
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Encrypt a message (from stdin) to every member and hand the blob to a carrier.
    Send {
        group: String,
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Every member with its verification state and who the admin is.
    Roster { group: String },
    /// Every group this vault is in.
    List,
    /// Give a group a different local name; names never leave the vault.
    Rename { group: String, new_name: String },
}

#[derive(Subcommand)]
enum RecoverCmd {
    /// Show n shares one at a time, each once, and write nothing. Any k of them rebuild the identity.
    Split { k: u8, n: u8 },
    /// On a device with no vault: rebuild the identity from k shares, read from files or one per line on stdin.
    Join {
        name: String,
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Every device of this identity, with the one you are on marked.
    List,
    /// On a new device with no vault yet: create one and print the request for a device that has the identity.
    Request,
    /// On a device that has the identity: read a request from a file or `-`, show its digits, ask, and print the enrolment.
    Enroll { name: String, request: String },
    /// On the new device: read the enrolment from a file or `-`, become the identity, and print what to hand back.
    Join { enrolment: String },
    /// On the witness: read what the new device handed back and write one blob per session, and one for the device.
    Connect {
        attach: String,
        /// Where the blobs go: `dir:<path>` writes one file per reader, `relay:<link file>` puts them all on one queue, `stdout` prints them in turn.
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Drop a device from every session. Its holder opens nothing sealed from here on.
    Revoke {
        name: String,
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
}

#[derive(Subcommand)]
enum IntroCmd {
    /// Print a fresh introduction to hand over out of band.
    Export {
        /// Also draw it as a QR code for a camera across the table.
        #[arg(long)]
        qr: bool,
    },
    /// Import a peer's introduction from a file, or `-` for stdin.
    Import { name: String, source: String },
}

/// Colour that switches itself off when the stream is not a terminal or NO_COLOR is set.
mod style {
    use super::*;
    use owo_colors::Style;

    fn paint(t: &str, stream: Stream, st: Style) -> String {
        t.if_supports_color(stream, |t| t.style(st)).to_string()
    }
    pub fn head(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().bold())
    }
    pub fn ok(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().green().bold())
    }
    pub fn warn(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().yellow().bold())
    }
    pub fn bad(t: &str) -> String {
        paint(t, Stream::Stderr, Style::new().red().bold())
    }
    pub fn dim(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().dimmed())
    }
    pub fn name(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().cyan().bold())
    }
    pub fn hash(t: &str) -> String {
        paint(t, Stream::Stdout, Style::new().magenta())
    }
    pub fn trust(t: MemberTrust) -> String {
        match t {
            MemberTrust::Verified => ok("Verified"),
            MemberTrust::Pending => warn("Pending "),
            MemberTrust::Changed => paint("Changed ", Stream::Stdout, Style::new().red().bold()),
            MemberTrust::Vouched => warn("Vouched "),
        }
    }
    pub fn state(st: PeerState) -> String {
        match st {
            PeerState::Verified => ok("Verified"),
            PeerState::Pending => warn("Pending "),
            PeerState::Changed => paint("Changed ", Stream::Stdout, Style::new().red().bold()),
        }
    }
    /// Twelve groups of digits, alternating colour so the eye tracks them while reading aloud.
    pub fn digits(spoken: &str) -> String {
        spoken
            .split(' ')
            .enumerate()
            .map(|(i, g)| {
                let st = if i % 2 == 0 { Style::new().bold().bright_white() } else { Style::new().bold().bright_cyan() };
                paint(g, Stream::Stdout, st)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn home() -> PathBuf {
    if let Ok(h) = std::env::var(config::vault::HOME_ENV) {
        return PathBuf::from(h);
    }
    let base = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    base.join(config::vault::HOME_DIR_NAME)
}

fn passphrase(confirm: bool) -> Result<String, Refuse> {
    if let Ok(p) = std::env::var(config::vault::PASSPHRASE_ENV) {
        return Ok(p);
    }
    let p = rpassword::prompt_password("vault passphrase: ").map_err(|_| Refuse::VaultIo)?;
    if confirm {
        let again = rpassword::prompt_password("again: ").map_err(|_| Refuse::VaultIo)?;
        if p != again {
            return Err(Refuse::NotConfirmed);
        }
    }
    Ok(p)
}

/// The passphrase for a process whose stdin is a protocol: the environment, or the controlling
/// terminal when the host leaves one, and never the stream.
fn passphrase_quietly() -> Result<String, Refuse> {
    if let Ok(p) = std::env::var(config::vault::PASSPHRASE_ENV) {
        return Ok(p);
    }
    let tty = rpassword::ConfigBuilder::new().input_file_path(config::vault::TTY).output_file_path(config::vault::TTY).build();
    rpassword::prompt_password_with_config("vault passphrase: ", tty).map_err(|_| Refuse::VaultIo)
}

/// Ask the human a yes-or-no question. On a terminal, ask there. Otherwise read the piped
/// answer, and only if the pipe held nothing fall back to the controlling terminal, so a wrapper
/// that closed stdin still reaches the human while a script's `echo yes |` still works.
fn ask_yes(prompt: &str) -> Result<bool, Refuse> {
    let mut line = String::new();
    if std::io::stdin().is_terminal() {
        print!("{prompt}");
        std::io::stdout().flush().map_err(|_| Refuse::VaultIo)?;
        std::io::stdin().read_line(&mut line).map_err(|_| Refuse::VaultIo)?;
    } else {
        line = String::from_utf8(read_stdin()?).unwrap_or_default();
        if line.trim().is_empty() {
            if let Ok(mut tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
                write!(tty, "{prompt}").map_err(|_| Refuse::VaultIo)?;
                tty.flush().map_err(|_| Refuse::VaultIo)?;
                let mut reader = std::io::BufReader::new(tty);
                std::io::BufRead::read_line(&mut reader, &mut line).map_err(|_| Refuse::VaultIo)?;
            }
        }
    }
    Ok(line.trim() == "yes")
}

fn read_stdin() -> Result<Vec<u8>, Refuse> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).map_err(|_| Refuse::VaultIo)?;
    Ok(buf)
}

/// The link file behind a `relay:` spec, which is the one carrier with an address to move.
fn relay_path(spec: &str) -> Option<&Path> {
    match spec.split_once(':') {
        Some(("relay", path)) => Some(Path::new(path)),
        _ => None,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// Seal to a peer over `spec`. Over a relay link whose queue is due, the next queue is made first
/// and its write half rides inside this message, as it does inside every message until the peer
/// has moved (docs/decisions/009-queue-rotation.md).
fn seal_over(core: &mut Core, name: &str, body: &[u8], spec: &str) -> Result<Blob, Refuse> {
    let Some(path) = relay_path(spec) else {
        return core.seal(name, body);
    };
    let mut link = RelayCarrier::open(path).map_err(|_| Refuse::CarrierIo)?;
    if link.link().due(unix_now()) {
        link.rotate().map_err(|_| Refuse::CarrierIo)?;
        eprintln!("{} {}", style::warn("·"), style::dim("your queue has been read long enough; the next one rides inside this message"));
    }
    match link.link().moving_to() {
        Some(to) => core.seal_moved(name, body, &to),
        None => core.seal(name, body),
    }
}

/// What a peer's message says about who reads what you send them, when it changed.
fn agent_reads_line(from: &str, reads: bool) -> String {
    if reads {
        format!("{from} says an assistant reads what you send them")
    } else {
        format!("{from} says no assistant reads what you send them now")
    }
}

/// A peer says where their next blobs should go: over a relay link, point the link there.
fn follow_move(spec: &str, from: &str, to: &str) {
    match relay_path(spec).map(|path| RelayCarrier::join(path, to)) {
        Some(Ok(link)) if link.send.as_ref().is_some_and(|h| h.to_text() == to) => {
            eprintln!("{} {}", style::warn("·"), style::dim(&format!("{from} moved their queue; your next message to them goes there")));
        }
        Some(_) => eprintln!("{} {}", style::warn("·"), style::dim(&format!("{from} moved their queue and the link file could not be changed; run `unheld relay join <file> {to}`"))),
        None => eprintln!("{} {}", style::warn("·"), style::dim(&format!("{from} moved their queue; run `unheld relay join <file> {to}`"))),
    }
}

fn carrier(spec: &str) -> Result<Box<dyn Carrier>, Refuse> {
    match spec.split_once(':') {
        Some(("file", path)) => Ok(Box::new(FileCarrier::new(path))),
        Some(("relay", path)) => Ok(Box::new(RelayCarrier::open(Path::new(path)).map_err(|_| Refuse::CarrierIo)?)),
        None if spec == "stdout" || spec == "stdin" => Ok(Box::new(StdioCarrier)),
        None if spec == "clipboard" => Ok(Box::new(ClipboardCarrier)),
        _ => Err(Refuse::CarrierIo),
    }
}

fn run(cli: Cli) -> Result<(), Refuse> {
    let dir = home().join(&cli.profile);
    match cli.cmd {
        Cmd::Id { cmd: IdCmd::New { name } } => {
            let pw = passphrase(true)?;
            let core = Core::create(&dir, &pw, &name)?;
            println!("{} {}  {}  {}", style::ok("✓"), style::head("identity created"), style::name(core.name()?), style::hash(&core.own_fingerprint_prefix()?));
            println!("{}", style::dim("keys live in this vault and nowhere else"));
        }
        Cmd::Id { cmd: IdCmd::Show } => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            let this = core.devices()?.into_iter().find(|d| d.is_this).map(|d| d.name).unwrap_or_default();
            println!("{}  {}  {}  {}", style::name(core.name()?), style::hash(&core.own_fingerprint_prefix()?), style::dim(&format!("device {this}")), style::dim(&dir.display().to_string()));
        }
        Cmd::Id { cmd: IdCmd::Rotate { carrier: spec } } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let outs = core.rotate()?;
            if outs.is_empty() {
                eprintln!("{} key rotated  {}; every peer sees Changed with your next message and must compare digits again", style::ok("✓"), style::hash(&core.own_fingerprint_prefix()?));
            } else {
                put_many(&spec, &outs)?;
                eprintln!("{} key rotated  {}; the blob above is for your other devices; every peer sees Changed with your next message", style::ok("✓"), style::hash(&core.own_fingerprint_prefix()?));
            }
        }
        Cmd::Intro { cmd: IntroCmd::Export { qr } } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let text = core.intro()?.to_text();
            if qr {
                let code = qrcode::QrCode::new(text.as_bytes()).map_err(|_| Refuse::TooLarge)?;
                let drawn = code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .dark_color(qrcode::render::unicode::Dense1x2::Light)
                    .light_color(qrcode::render::unicode::Dense1x2::Dark)
                    .build();
                eprintln!("{drawn}");
            }
            println!("{text}");
        }
        Cmd::Intro { cmd: IntroCmd::Import { name, source } } => {
            let text = if source == "-" {
                String::from_utf8(read_stdin()?).map_err(|_| Refuse::BadIntro)?
            } else {
                std::fs::read_to_string(&source).map_err(|_| Refuse::VaultIo)?
            };
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let peer = core.import(&name, &Intro::from_text(&text)?)?;
            println!("{} {} staged as {}", style::ok("✓"), style::name(&peer.name), style::state(peer.state));
            println!("{}", style::dim(&format!("next: unheld verify {}   (compare the digits out loud)", peer.name)));
        }
        Cmd::Verify { name, qr } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let fp = core.fingerprint(&name)?;
            if qr {
                let code = qrcode::QrCode::new(fp.0.as_bytes()).map_err(|_| Refuse::Protocol)?;
                let drawn = code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .dark_color(qrcode::render::unicode::Dense1x2::Light)
                    .light_color(qrcode::render::unicode::Dense1x2::Dark)
                    .build();
                println!("{drawn}");
            }
            println!("{} {}", style::head("safety number with"), style::name(&name));
            println!("{}\n", style::dim("read these aloud and listen to theirs; they must be identical"));
            println!("  {}\n", style::digits(&fp.spoken()));
            let confirmed = ask_yes("did every group match on both sides? [yes/NO] ")?;
            let peer = core.verify(&name, confirmed)?;
            println!("{} {} is {}", style::ok("✓"), style::name(&peer.name), style::state(peer.state));
        }
        Cmd::Peers { cmd: Some(PeersCmd::GrantAgent { name }) } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let p = core.grant_agent(&name, true)?;
            println!("{} an agent may read and send with {} through {}", style::ok("✓"), style::name(&p.name), style::dim("unheld mcp"));
            println!("{}", style::dim(&format!("{} is told inside your next message; revoke with `unheld peers revoke-agent`", p.name)));
        }
        Cmd::Peers { cmd: Some(PeersCmd::RevokeAgent { name }) } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let p = core.grant_agent(&name, false)?;
            println!("{} no agent reads or sends with {}", style::ok("✓"), style::name(&p.name));
            println!("{}", style::dim(&format!("{} is told inside your next message", p.name)));
        }
        Cmd::Peers { cmd: None } => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            let peers = core.peers();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&peers).map_err(|_| Refuse::Protocol)?);
            } else {
                if peers.is_empty() {
                    println!("{}", style::dim("no peers yet; import an introduction"));
                }
                for p in peers {
                    println!(
                        "{} {:<16} {}  {}",
                        style::state(p.state),
                        style::name(&p.name),
                        style::hash(&p.fingerprint_prefix),
                        style::dim(&format!(
                            "sessions {}  intro {}{}{}",
                            p.sessions,
                            if p.has_intro { "unused" } else { "consumed" },
                            if p.agent_access { "  agent" } else { "" },
                            if p.agent_reads { "  their agent" } else { "" }
                        ))
                    );
                }
            }
        }
        Cmd::Send { name, carrier: spec } => {
            if std::io::stdin().is_terminal() {
                eprintln!("{}", style::dim(&format!("message to {name}: type, press Enter, then Ctrl-D to seal")));
            }
            let body = read_stdin()?;
            if body.iter().all(|b| b.is_ascii_whitespace()) {
                return Err(Refuse::EmptyMessage);
            }
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            if core.peer(&name)?.agent_reads {
                eprintln!("{} {}", style::warn("·"), style::dim(&format!("an assistant reads what {name} receives")));
            }
            let blob = seal_over(&mut core, &name, &body, &spec)?;
            carrier(&spec)?.put(&blob).map_err(carrier_refusal)?;
            if let Some((kind, path)) = spec.split_once(':') {
                let shown = Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                eprintln!("{} {}", style::ok("✓"), style::dim(&format!("sealed {} bytes into {kind} {shown}", blob.len())));
            }
        }
        Cmd::Open { carrier: spec } => {
            let blob = carrier(&spec)?.get().map_err(carrier_refusal)?;
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            for m in core.open(&blob)? {
                if let Some(change) = &m.change {
                    eprintln!("{} {}", style::warn("·"), change);
                } else if m.session_started {
                    eprintln!("{}", style::dim(&format!("· session started by {}", m.from)));
                } else {
                    let who = match (&m.group, &m.vouched_by) {
                        (Some(g), Some(v)) => format!("{} {} {}", style::dim(&format!("[{g}]")), style::warn(&m.from), style::dim(&format!("(vouched by {v}) ›"))),
                        (Some(g), None) => format!("{} {}", style::dim(&format!("[{g}]")), style::name(&format!("{} ›", m.from))),
                        _ => style::name(&format!("{} ›", m.from)),
                    };
                    let text = String::from_utf8_lossy(&m.body);
                    println!("{who} {}", text.strip_suffix('\n').unwrap_or(&text));
                }
                if let Some(to) = &m.moved_to {
                    follow_move(&spec, &m.from, to);
                }
                if let Some(reads) = m.agent_reads {
                    eprintln!("{} {}", style::warn("·"), agent_reads_line(&m.from, reads));
                }
            }
        }
        Cmd::Forget { name } => {
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let n = core.forget(&name)?;
            match core.peer(&name) {
                Ok(p) => println!("{} {} sessions with {} ended; keys deleted; {} stays {}", style::ok("✓"), n, style::name(&name), style::name(&name), style::state(p.state)),
                Err(_) => println!("{} left {}; its keys are deleted. the others still list you until the admin removes you", style::ok("✓"), style::name(&name)),
            }
        }
        Cmd::Group { cmd } => group_cmd(cmd, &dir, cli.json)?,
        Cmd::Devices { cmd } => device_cmd(cmd, &dir, cli.json)?,
        Cmd::Recover { cmd: RecoverCmd::Split { k, n } } => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            let shares = core.split(k, n)?;
            let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
            eprintln!("{} {}", style::head(&format!("{n} shares, any {k} rebuild the identity")), style::dim("each is shown once and written nowhere; hand each to one person"));
            for (i, s) in shares.iter().enumerate() {
                if interactive {
                    print!("\x1b[2J\x1b[H");
                }
                println!("{} {}", style::warn(&format!("share {} of {n}", i + 1)), style::dim("(copy it now)"));
                println!("{}", s.to_text().as_str());
                if interactive && i + 1 < shares.len() {
                    let _ = ask_yes("press Enter when it is copied; it will leave the screen ");
                }
            }
            if interactive {
                print!("\x1b[2J\x1b[H");
            }
            eprintln!("{} {} shares shown; this vault is unchanged and holds none of them", style::ok("✓"), n);
        }
        Cmd::Recover { cmd: RecoverCmd::Join { name, shares: sources } } => {
            let texts: Vec<String> = if sources.is_empty() {
                String::from_utf8(read_stdin()?).map_err(|_| Refuse::BadShare)?.lines().map(str::to_owned).filter(|l| !l.trim().is_empty()).collect()
            } else {
                sources.iter().map(|p| std::fs::read_to_string(p).map_err(|_| Refuse::VaultIo)).collect::<Result<_, _>>()?
            };
            let shares = texts.iter().map(|t| Share::from_text(t)).collect::<Result<Vec<_>, _>>()?;
            let pw = passphrase(true)?;
            let core = Core::recover(&dir, &pw, &name, &shares)?;
            println!("{} {}  {}  {}", style::ok("✓"), style::head("identity rebuilt"), style::name(core.name()?), style::hash(&core.own_fingerprint_prefix()?));
            println!("{}", style::dim("peers who verified you still do; import their introductions and compare digits again to talk"));
        }
        Cmd::Duress => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            let d = rpassword::prompt_password("duress passphrase: ").map_err(|_| Refuse::VaultIo)?;
            let again = rpassword::prompt_password("again: ").map_err(|_| Refuse::VaultIo)?;
            if d != again {
                return Err(Refuse::NotConfirmed);
            }
            core.set_duress(&d)?;
            println!("{} duress passphrase set; unlocking with it destroys this vault and says only that it could not be opened", style::ok("✓"));
        }
        Cmd::Wipe => {
            if !ask_yes("destroy this vault and every key in it? [yes/NO] ")? {
                return Err(Refuse::NotConfirmed);
            }
            unheld_core::wipe(&dir)?;
            println!("{} vault destroyed", style::ok("✓"));
        }
        Cmd::Inspect { carrier: spec } => {
            let blob = carrier(&spec)?.get().map_err(carrier_refusal)?;
            let outside = unheld_core::inspect(&blob);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&outside).map_err(|_| Refuse::Protocol)?);
            } else {
                println!("{} {}", style::head("an outsider holding this blob can read:"), style::dim(&format!("bucket {} bytes", outside.bucket)));
                for p in &outside.parts {
                    match p {
                        unheld_core::OutsidePart::Message { wire_format, group_id_prefix, epoch, content_type } => {
                            println!("  {} {wire_format}  session {}  epoch {epoch}  {content_type}", style::warn("MLS message"), style::hash(group_id_prefix));
                        }
                        unheld_core::OutsidePart::Welcome { ciphersuite, recipients } => {
                            println!("  {} {ciphersuite}  recipients {recipients}", style::warn("MLS welcome"));
                        }
                        unheld_core::OutsidePart::Introduction => println!("  {}", style::warn("an introduction (public by design)")),
                        unheld_core::OutsidePart::Opaque => println!("  {}", style::ok("nothing: opaque bytes")),
                    }
                }
                println!("{}", style::dim("and never: who sent it, to whom, or what it says (docs/decisions/002-carrier-view.md)"));
            }
        }
        Cmd::Relay { cmd: RelayCmd::New { address, file } } => {
            let carrier = RelayCarrier::create(&address, Path::new(&file)).map_err(|_| Refuse::CarrierIo)?;
            let link = carrier.link();
            let at = link.receive.as_ref().ok_or(Refuse::CarrierIo)?;
            eprintln!("{} {}  {}", style::ok("✓"), style::head("your queue is on"), style::hash(&at.at.relay));
            eprintln!("{}", style::dim("hand the line below to the one person who will send to you, by any channel, and run `unheld relay join` with theirs:"));
            println!("{}", link.invitation().ok_or(Refuse::CarrierIo)?);
            eprintln!("{}", style::dim(&format!("for a group, hand {file} itself to every member instead; each passes -c relay:{file}")));
        }
        Cmd::Relay { cmd: RelayCmd::Join { file, invitation } } => {
            let link = RelayCarrier::join(Path::new(&file), &invitation).map_err(|_| Refuse::CarrierIo)?;
            let to = link.send.as_ref().ok_or(Refuse::CarrierIo)?;
            match &link.receive {
                Some(from) => println!("{} {}  {}  {}", style::ok("✓"), style::head(&format!("{file} sends to")), style::hash(&to.at.relay), style::dim(&format!("and receives on {}", from.at.relay))),
                None => println!("{} {}  {}  {}", style::ok("✓"), style::head(&format!("{file} sends to")), style::hash(&to.at.relay), style::dim("and receives nowhere until `unheld relay new` makes your own queue")),
            }
        }
        Cmd::About => {
            println!("{} {}  {}", style::head("unheld"), env!("CARGO_PKG_VERSION"), style::dim("proof of concept; unsigned, unlogged, unaudited"));
            println!("{} OpenMLS, {:?}", style::dim("ratchet "), config::mls::CIPHERSUITE);
            println!("{} a device someone else controls, a careless or hostile correspondent, a coerced person", style::warn("not protected:"));
        }
        Cmd::Mcp { carrier: spec } => {
            let c = carrier(&spec)?;
            let core = Core::unlock(&dir, &passphrase_quietly()?)?;
            mcp::serve(core, c, &spec)?;
        }
    }
    Ok(())
}

/// Text handed over by hand: a file path, or `-` for stdin.
fn read_text(source: &str) -> Result<String, Refuse> {
    if source == "-" {
        String::from_utf8(read_stdin()?).map_err(|_| Refuse::BadIntro)
    } else {
        std::fs::read_to_string(source).map_err(|_| Refuse::VaultIo)
    }
}

/// Several blobs for several readers: `dir:<path>` writes `<reader>.blob` in that directory,
/// `stdout` prints each after a line naming its reader on stderr.
/// What the carrier's failure is, in the client's words.
fn carrier_refusal(e: unheld_blob::CarrierError) -> Refuse {
    match e {
        unheld_blob::CarrierError::Empty => Refuse::NothingToOpen,
        unheld_blob::CarrierError::Io(_) => Refuse::CarrierIo,
        unheld_blob::CarrierError::Blob(_) => Refuse::BadBlob,
        unheld_blob::CarrierError::Disordered { expected, got } => Refuse::Gap(expected, got),
        unheld_blob::CarrierError::Refused(why) => Refuse::CarrierRefused(why),
    }
}

fn put_many(spec: &str, outs: &[Outbound]) -> Result<(), Refuse> {
    match spec.split_once(':') {
        Some(("dir", path)) => {
            std::fs::create_dir_all(path).map_err(|_| Refuse::CarrierIo)?;
            for o in outs {
                let file = Path::new(path).join(format!("{}.blob", o.to.label()));
                FileCarrier::new(file.display().to_string()).put(&o.blob).map_err(|_| Refuse::CarrierIo)?;
                eprintln!("{} {}", style::ok("✓"), style::dim(&format!("for {}: {} bytes into {}", o.to.label(), o.blob.len(), file.display())));
            }
            Ok(())
        }
        None if spec == "stdout" => {
            for o in outs {
                eprintln!("{}", style::dim(&format!("· for {}:", o.to.label())));
                StdioCarrier.put(&o.blob).map_err(|_| Refuse::CarrierIo)?;
            }
            Ok(())
        }
        Some(("relay", path)) => {
            // One link, every reader: each collects all of them and opens the one that is theirs.
            let mut queue = RelayCarrier::open(Path::new(path)).map_err(|_| Refuse::CarrierIo)?;
            for o in outs {
                queue.put(&o.blob).map_err(carrier_refusal)?;
                eprintln!("{} {}", style::ok("✓"), style::dim(&format!("for {}: {} bytes to the relay", o.to.label(), o.blob.len())));
            }
            Ok(())
        }
        _ => Err(Refuse::CarrierIo),
    }
}

fn device_cmd(cmd: DeviceCmd, dir: &Path, json: bool) -> Result<(), Refuse> {
    match cmd {
        DeviceCmd::List => {
            let core = Core::unlock(dir, &passphrase(false)?)?;
            let ds = core.devices()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ds).map_err(|_| Refuse::Protocol)?);
            } else {
                for d in &ds {
                    let note = match (d.is_this, d.revoked) {
                        (true, _) => "this device".to_owned(),
                        (_, true) => "revoked".to_owned(),
                        _ => String::new(),
                    };
                    let label = if d.revoked { style::dim(&d.name) } else { style::name(&d.name) };
                    println!("{} {:<16} {}  {}", if d.revoked { style::warn("✗") } else { style::ok("✓") }, label, style::hash(&d.fingerprint_prefix), style::dim(&note));
                }
            }
        }
        DeviceCmd::Request => {
            let pw = passphrase(true)?;
            let (_core, request) = Core::create_device(dir, &pw)?;
            eprintln!("{} {}", style::head("this device shows"), style::dim("(the device that enrols you must show the same digits)"));
            eprintln!("\n  {}\n", style::digits(&request.fingerprint()?.spoken()));
            eprintln!("{}", style::dim("hand the request below to a device that has the identity: unheld devices enroll <name> <file>"));
            println!("{}", request.to_text());
        }
        DeviceCmd::Enroll { name, request } => {
            let request = Request::from_text(&read_text(&request)?)?;
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            eprintln!("{} {}", style::head("the new device must show exactly"), style::name(&name));
            eprintln!("\n  {}\n", style::digits(&request.fingerprint()?.spoken()));
            let confirmed = ask_yes("does the new device show these digits, every group? [yes/NO] ")?;
            let enrolment = core.enroll(&name, &request, confirmed)?;
            eprintln!("{} {} enrolled; hand the enrolment below to it: unheld devices join <file>", style::ok("✓"), style::name(&name));
            println!("{}", enrolment.to_text());
        }
        DeviceCmd::Join { enrolment } => {
            let enrolment = Enrolment::from_text(&read_text(&enrolment)?)?;
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let attach = core.join_device(&enrolment)?;
            eprintln!("{} this device is now {}; hand what follows back to the witness: unheld devices connect <file>", style::ok("✓"), style::name(core.name()?));
            println!("{}", attach.to_text());
        }
        DeviceCmd::Connect { attach, carrier: spec } => {
            let attach = Attach::from_text(&read_text(&attach)?)?;
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let outs = core.connect_device(&attach)?;
            put_many(&spec, &outs)?;
            eprintln!("{} {} blobs: one for each session's readers, and the last for the new device", style::ok("✓"), outs.len());
        }
        DeviceCmd::Revoke { name, carrier: spec } => {
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let outs = core.revoke_device(&name)?;
            put_many(&spec, &outs)?;
            eprintln!("{} {} revoked; {} blobs, one for each session's readers", style::ok("✓"), style::name(&name), outs.len());
        }
    }
    Ok(())
}

fn put(spec: &str, blob: &unheld_blob::Blob, what: &str) -> Result<(), Refuse> {
    carrier(spec)?.put(blob).map_err(|_| Refuse::CarrierIo)?;
    if let Some((kind, path)) = spec.split_once(':') {
        let shown = Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        eprintln!("{} {}", style::ok("✓"), style::dim(&format!("{what}: {} bytes into {kind} {shown}", blob.len())));
    } else if spec == "clipboard" {
        eprintln!("{} {}", style::ok("✓"), style::dim(&format!("{what}: {} bytes on the clipboard", blob.len())));
    }
    Ok(())
}

/// One line per member, so the state of everyone who will read a message is seen every time (L18).
fn show_roster(r: &unheld_core::Roster) {
    println!("{} {}  {}", style::head(&r.name), style::dim(&format!("epoch {}", r.epoch)), style::dim(&format!("admin {}{}", r.admin, if r.i_am_admin { " (you)" } else { "" })));
    for m in &r.members {
        let label = if m.trust == MemberTrust::Vouched { style::warn(&m.label) } else { style::name(&m.label) };
        let note = match (m.is_me, m.trust) {
            (true, _) => "you".to_owned(),
            (false, MemberTrust::Vouched) => format!("vouched for by {}; you never compared digits with them", r.admin),
            _ => String::new(),
        };
        let devices = if m.devices > 1 { format!("{} devices  ", m.devices) } else { String::new() };
        println!("  {} {:<16} {}{}", style::trust(m.trust), label, style::dim(&devices), style::dim(&note));
    }
}

fn group_cmd(cmd: GroupCmd, dir: &Path, json: bool) -> Result<(), Refuse> {
    match cmd {
        GroupCmd::New { name, peers, carrier: spec } => {
            let ordered = carrier(&spec)?.ordered();
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let names: Vec<&str> = peers.iter().map(String::as_str).collect();
            let welcome = core.group_new(&name, &names, ordered)?;
            put(&spec, &welcome, "welcome")?;
            eprintln!("{} {} started with {} members; hand the welcome to each of them", style::ok("✓"), style::name(&name), names.len() + 1);
        }
        GroupCmd::Add { group, peer, carrier: spec, welcome: wspec } => {
            let ordered = carrier(&spec)?.ordered();
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let added = core.group_add(&group, &peer, ordered)?;
            put(&spec, &added.for_group, "commit for the members")?;
            put(&wspec, &added.for_newcomer, &format!("welcome for {peer}"))?;
            eprintln!("{} {} added to {}; the first blob is for the members, the second for {}", style::ok("✓"), style::name(&peer), style::name(&group), style::name(&peer));
        }
        GroupCmd::Remove { group, member, carrier: spec } => {
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let commit = core.group_remove(&group, &member)?;
            put(&spec, &commit, "commit for the members")?;
            eprintln!("{} {} removed from {}; they open nothing sealed from here on", style::ok("✓"), style::name(&member), style::name(&group));
        }
        GroupCmd::Send { group, carrier: spec } => {
            let mut out = carrier(&spec)?;
            if std::io::stdin().is_terminal() {
                eprintln!("{}", style::dim(&format!("message to {group}: type, press Enter, then Ctrl-D to seal")));
            }
            let body = read_stdin()?;
            if body.iter().all(|b| b.is_ascii_whitespace()) {
                return Err(Refuse::EmptyMessage);
            }
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            let roster = core.roster(&group)?;
            let readers: Vec<String> = roster
                .members
                .iter()
                .filter(|m| !m.is_me)
                .map(|m| if m.trust == MemberTrust::Vouched { format!("{} (vouched by {})", m.label, roster.admin) } else { format!("{} ({:?})", m.label, m.trust) })
                .collect();
            eprintln!("{}", style::dim(&format!("readers: {}", readers.join(", "))));
            let blob = core.group_seal(&group, &body)?;
            out.put(&blob).map_err(|_| Refuse::CarrierIo)?;
            if spec != "stdout" {
                eprintln!("{} {}", style::ok("✓"), style::dim(&format!("sealed {} bytes for {} readers", blob.len(), readers.len())));
            }
        }
        GroupCmd::Roster { group } => {
            let core = Core::unlock(dir, &passphrase(false)?)?;
            let r = core.roster(&group)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).map_err(|_| Refuse::Protocol)?);
            } else {
                show_roster(&r);
            }
        }
        GroupCmd::List => {
            let core = Core::unlock(dir, &passphrase(false)?)?;
            let gs = core.groups();
            if json {
                println!("{}", serde_json::to_string_pretty(&gs).map_err(|_| Refuse::Protocol)?);
            } else if gs.is_empty() {
                println!("{}", style::dim("no groups; start one with `group new <name> <peer> <peer>...`"));
            } else {
                for r in &gs {
                    show_roster(r);
                }
            }
        }
        GroupCmd::Rename { group, new_name } => {
            let mut core = Core::unlock(dir, &passphrase(false)?)?;
            core.group_rename(&group, &new_name)?;
            println!("{} {} is now {}", style::ok("✓"), style::name(&group), style::name(&new_name));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e}", style::bad("refused:"));
            ExitCode::from(2)
        }
    }
}
