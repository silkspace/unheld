#![forbid(unsafe_code)]
//! `unheld-relay`: one static binary that holds queues of ciphertext and nothing else.

use clap::{Parser, Subcommand};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use unheld_relay::store::{Limits, Relay};
use unheld_relay::tls::Identity;
use unheld_relay::{config, RelayError};

#[derive(Parser)]
#[command(name = "unheld-relay", about = "A store of queues that orders blobs and knows nothing else.")]
struct Cli {
    /// Where the relay keeps its certificate, its key and its queues.
    #[arg(long, default_value = "relay")]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make the relay's certificate and key and print the address clients pin.
    Init {
        /// The host name or address clients will reach this relay by.
        host: String,
        /// The port, for the address printed.
        #[arg(long, default_value_t = 4443)]
        port: u16,
    },
    /// Serve queues.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:4443")]
        listen: String,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("refused: {e}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), RelayError> {
    match cli.cmd {
        Cmd::Init { host, port } => {
            if cli.dir.join(config::files::KEY).exists() {
                return Err(RelayError::Refused("this directory already holds a relay identity"));
            }
            let identity = Identity::generate(&host)?;
            identity.save(&cli.dir)?;
            println!("{}{host}:{port}#{}", config::SCHEME, identity.pin().to_hex());
        }
        Cmd::Serve { listen } => {
            let identity = Identity::load(&cli.dir)?;
            let relay = Arc::new(Relay::open(&cli.dir, Limits::default())?);
            let listener = TcpListener::bind(&listen)?;
            eprintln!("serving on {listen}, pin {}", identity.pin().to_hex());
            unheld_relay::server::serve(listener, relay, identity.server_config()?)?;
        }
    }
    Ok(())
}
