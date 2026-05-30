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

/// A matched wallet, serialized with the original camelCase column names
/// (`mnemonicPhrase`, `privateKey`, `bitcoinAddress`, `ethereumAddress`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the on-disk field names to the original `wallet.ts` CSV columns.
    /// Without `rename_all = "camelCase"` serde emits the Rust snake_case
    /// identifiers, silently breaking downstream tooling — this guards it.
    #[test]
    fn serializes_with_camelcase_columns() -> Result<()> {
        let line = serde_json::to_string(&Record {
            mnemonic_phrase: "m",
            private_key: "k",
            bitcoin_address: "1b",
            ethereum_address: "0xe",
            description: "d",
        })?;
        assert_eq!(
            line,
            r#"{"mnemonicPhrase":"m","privateKey":"k","bitcoinAddress":"1b","ethereumAddress":"0xe","description":"d"}"#
        );
        Ok(())
    }
}
