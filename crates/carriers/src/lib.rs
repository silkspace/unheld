#![forbid(unsafe_code)]
//! Carriers move blobs. This crate depends on `unheld-blob`, on `unheld-relay` for the one
//! ordered carrier, and on nothing that can name a key.

use std::io::{Read, Write};
use std::path::PathBuf;
use unheld_blob::{Blob, Carrier, CarrierError};

/// The ordered carrier: a queue on a relay, over TLS pinned to the relay's certificate (L19).
pub use unheld_relay::carrier::RelayCarrier;

/// A file holding one blob as text. Put overwrites, get reads.
pub struct FileCarrier {
    path: PathBuf,
}

impl FileCarrier {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Carrier for FileCarrier {
    fn put(&mut self, blob: &Blob) -> Result<(), CarrierError> {
        let mut text = blob.to_text();
        text.push('\n');
        std::fs::write(&self.path, text)?;
        Ok(())
    }

    fn get(&mut self) -> Result<Blob, CarrierError> {
        let text = std::fs::read_to_string(&self.path)?;
        if text.trim().is_empty() {
            return Err(CarrierError::Empty);
        }
        Ok(Blob::from_text(&text)?)
    }
}

/// Standard output for put, standard input for get, so blobs flow through pipes.
pub struct StdioCarrier;

impl Carrier for StdioCarrier {
    fn put(&mut self, blob: &Blob) -> Result<(), CarrierError> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", blob.to_text())?;
        Ok(())
    }

    fn get(&mut self) -> Result<Blob, CarrierError> {
        let mut text = String::new();
        std::io::stdin().lock().read_to_string(&mut text)?;
        if text.trim().is_empty() {
            return Err(CarrierError::Empty);
        }
        Ok(Blob::from_text(&text)?)
    }
}

/// The system clipboard. Put copies the blob as text, get pastes it. What the clipboard
/// holds is ciphertext, so a clipboard manager or a synced clipboard learns nothing.
pub struct ClipboardCarrier;

impl Carrier for ClipboardCarrier {
    fn put(&mut self, blob: &Blob) -> Result<(), CarrierError> {
        let mut cb = arboard::Clipboard::new().map_err(|_| CarrierError::Empty)?;
        cb.set_text(blob.to_text()).map_err(|_| CarrierError::Empty)?;
        Ok(())
    }

    fn get(&mut self) -> Result<Blob, CarrierError> {
        let mut cb = arboard::Clipboard::new().map_err(|_| CarrierError::Empty)?;
        let text = cb.get_text().map_err(|_| CarrierError::Empty)?;
        if text.trim().is_empty() {
            return Err(CarrierError::Empty);
        }
        Ok(Blob::from_text(&text)?)
    }
}
