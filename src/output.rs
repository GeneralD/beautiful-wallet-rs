//! NDJSON sink for matched wallets.
//!
//! One JSON object per line, appended atomically under a mutex. Field names
//! mirror the original `wallet.ts` CSV columns so downstream tooling is
//! unchanged; NDJSON (over CSV) survives an interrupted run without a torn
//! final record and streams line-by-line.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// A matched wallet, serialized with the original camelCase column names.
#[derive(Serialize)]
pub struct Record<'a> {
    pub mnemonic_phrase: &'a str,
    pub private_key: &'a str,
    pub bitcoin_address: &'a str,
    pub ethereum_address: &'a str,
    pub description: &'a str,
}

pub struct NdjsonSink {
    file: Mutex<File>,
}

impl NdjsonSink {
    /// Open (creating if needed) the NDJSON file for appending.
    pub fn appending(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Append one record as a single NDJSON line. Hits are rare, so the lock
    /// is uncontended in practice.
    pub fn append(&self, record: &Record<'_>) -> Result<()> {
        let mut line = serde_json::to_string(record).context("serialize record")?;
        line.push('\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("sink poisoned"))?;
        file.write_all(line.as_bytes()).context("write record")?;
        Ok(())
    }
}
