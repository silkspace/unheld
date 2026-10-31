#![forbid(unsafe_code)]
//! The command-line client. Each subcommand is one kernel verb; every refusal is exit code 2.

use clap::{Parser, Subcommand};
use owo_colors::{OwoColorize, Stream};
use unheld_core::vocab::PeerState;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
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
    /// Read a blob the way a carrier would, with no vault and no key, and print what it learns.
    Inspect {
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
            println!("{} {}  {}  {}", style::ok("✓"), style::head("identity created"), style::name(core.name()?), style::hash(&core.own_fingerprint_prefix()?));
            println!("{}", style::dim("keys live in this vault and nowhere else"));
        }
        Cmd::Id { cmd: IdCmd::Show } => {
            let core = Core::unlock(&dir, &passphrase(false)?)?;
            println!("{}  {}  {}", style::name(core.name()?), style::hash(&core.own_fingerprint_prefix()?), style::dim(&dir.display().to_string()));
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
        Cmd::Peers => {
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
                        style::dim(&format!("sessions {}  intro {}", p.sessions, if p.has_intro { "unused" } else { "consumed" }))
                    );
                }
            }
        }
        Cmd::Send { name, carrier: spec } => {
            let mut out = carrier(&spec)?;
            if std::io::stdin().is_terminal() {
                eprintln!("{}", style::dim(&format!("message to {name}: type, press Enter, then Ctrl-D to seal")));
            }
            let body = read_stdin()?;
            if body.iter().all(|b| b.is_ascii_whitespace()) {
                return Err(Refuse::EmptyMessage);
            }
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            let blob = core.seal(&name, &body)?;
            out.put(&blob).map_err(|_| Refuse::CarrierIo)?;
            if let Some((kind, path)) = spec.split_once(':') {
                let shown = Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                eprintln!("{} {}", style::ok("✓"), style::dim(&format!("sealed {} bytes into {kind} {shown}", blob.len())));
            }
        }
        Cmd::Open { carrier: spec } => {
            let blob = carrier(&spec)?.get().map_err(|e| match e {
                unheld_blob::CarrierError::Empty => Refuse::NothingToOpen,
                unheld_blob::CarrierError::Io(_) => Refuse::CarrierIo,
                unheld_blob::CarrierError::Blob(_) => Refuse::BadBlob,
            })?;
            let mut core = Core::unlock(&dir, &passphrase(false)?)?;
            for m in core.open(&blob)? {
                if m.session_started {
                    eprintln!("{}", style::dim(&format!("· session started by {}", m.from)));
                } else {
                    println!("{} {}", style::name(&format!("{} ›", m.from)), String::from_utf8_lossy(&m.body));
                }
            }
        }
        Cmd::Inspect { carrier: spec } => {
            let blob = carrier(&spec)?.get().map_err(|e| match e {
                unheld_blob::CarrierError::Empty => Refuse::NothingToOpen,
                unheld_blob::CarrierError::Io(_) => Refuse::CarrierIo,
                unheld_blob::CarrierError::Blob(_) => Refuse::BadBlob,
            })?;
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
        Cmd::About => {
            println!("{} {}  {}", style::head("unheld"), env!("CARGO_PKG_VERSION"), style::dim("proof of concept; unsigned, unlogged, unaudited"));
            println!("{} OpenMLS, {:?}", style::dim("ratchet "), config::mls::CIPHERSUITE);
            println!("{} a device someone else controls, a careless or hostile correspondent, a coerced person", style::warn("not protected:"));
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
