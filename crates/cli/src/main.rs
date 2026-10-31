#![forbid(unsafe_code)]
//! The command-line client. Each subcommand is one kernel verb; every refusal is exit code 2.

use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use unheld_blob::Carrier;
use unheld_carriers::{FileCarrier, StdioCarrier};
use unheld_core::config;
use unheld_core::vocab::Refuse;
use unheld_core::{Core, Intro};

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
    /// List peers and their verification state.
    Peers,
    /// Encrypt a message (from stdin) to a verified peer and hand the blob to a carrier.
    Send {
        name: String,
        /// Carrier: `stdout` or `file:<path>`.
        #[arg(short, long, default_value = "stdout")]
        carrier: String,
    },
    /// Take a blob from a carrier and decrypt it.
    Open {
        /// Carrier: `stdin` or `file:<path>`.
        #[arg(short, long, default_value = "stdin")]
        carrier: String,
    },
    /// This build and what is known about it.
    About,
}

#[derive(Subcommand)]
enum IdCmd {
    New { name: String },
    Show,
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

fn read_stdin() -> Result<Vec<u8>, Refuse> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).map_err(|_| Refuse::VaultIo)?;
    Ok(buf)
}

fn carrier(spec: &str) -> Result<Box<dyn Carrier>, Refuse> {
    match spec.split_once(':') {
        Some(("file", path)) => Ok(Box::new(FileCarrier::new(path))),
        None if spec == "stdout" || spec == "stdin" => Ok(Box::new(StdioCarrier)),
        _ => Err(Refuse::BadBlob),
    }
}

fn run(cli: Cli) -> Result<(), Refuse> {
    let dir = home().join(&cli.profile);
    match cli.cmd {
        Cmd::Id { cmd: IdCmd::New { name } } => {
            let pw = passphrase(true)?;
            let core = Core::create(&dir, &pw, &name)?;
            println!("identity {} created; public prefix {}", core.name()?, core.own_fingerprint_prefix()?);
        }
        Cmd::Id { cmd: IdCmd::Show } => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            println!("{}  {}  {}", core.name()?, core.own_fingerprint_prefix()?, dir.display());
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
            println!("{} staged as {:?}; run `unheld verify {}`", peer.name, peer.state, peer.name);
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
            println!("read these aloud and listen to theirs:\n\n  {}\n", fp.spoken());
            let confirmed = if std::io::stdin().is_terminal() {
                print!("did every group match on both sides? [yes/NO] ");
                std::io::stdout().flush().map_err(|_| Refuse::VaultIo)?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).map_err(|_| Refuse::VaultIo)?;
                line.trim() == "yes"
            } else {
                String::from_utf8(read_stdin()?).map(|s| s.trim() == "yes").unwrap_or(false)
            };
            let peer = core.verify(&name, confirmed)?;
            println!("{} is {:?}", peer.name, peer.state);
        }
        Cmd::Peers => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            let peers = core.peers();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&peers).map_err(|_| Refuse::Protocol)?);
            } else {
                for p in peers {
                    println!("{:<16} {:<9} {}  sessions {}  intro {}", p.name, format!("{:?}", p.state), p.fingerprint_prefix, p.sessions, if p.has_intro { "unused" } else { "consumed" });
                }
            }
        }
        Cmd::Send { name, carrier: spec } => {
            let body = read_stdin()?;
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let blob = core.seal(&name, &body)?;
            carrier(&spec)?.put(&blob).map_err(|_| Refuse::VaultIo)?;
        }
        Cmd::Open { carrier: spec } => {
            let blob = carrier(&spec)?.get().map_err(|_| Refuse::BadBlob)?;
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            for m in core.open(&blob)? {
                if m.session_started {
                    eprintln!("[session started by {}]", m.from);
                } else {
                    println!("{}: {}", m.from, String::from_utf8_lossy(&m.body));
                }
            }
        }
        Cmd::About => {
            println!("unheld {}  proof of concept; unsigned, unlogged, unaudited", env!("CARGO_PKG_VERSION"));
            println!("ratchet: OpenMLS, ciphersuite {:?}", config::mls::CIPHERSUITE);
            println!("not protected: a device someone else controls, a careless or hostile correspondent, a coerced person");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("refused: {e}");
            ExitCode::from(2)
        }
    }
}
