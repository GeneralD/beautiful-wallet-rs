//! beautiful-wallet — fast, parallel BIP39 vanity Ethereum/Bitcoin wallet miner.
//!
//! A Rust port of `GeneralD/beautiful-wallet` (TypeScript). The browser/front-end
//! parts of the original are intentionally omitted — this is the mining core only.
//!
//! Each worker thread runs an independent infinite loop (the search is
//! embarrassingly parallel): generate a fresh BIP39 wallet, test its EIP-55
//! address against the vanity pattern set, and append any match as NDJSON.
//! Throughput is reported once per second from a single reporter thread, so the
//! workers never contend on stdout (the original `console.log` per iteration was
//! a real bottleneck at multi-core speeds).

mod address;
mod output;
mod pattern;
mod wallet;

use anyhow::Result;
use clap::Parser;
use output::{NdjsonSink, Record};
use pattern::PatternSet;
use rand::SeedableRng;
use rand::rngs::StdRng;
use secp256k1::Secp256k1;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use wallet::Wallet;

#[derive(Parser)]
#[command(
    version,
    about = "Parallel BIP39 vanity wallet miner (Rust port of beautiful-wallet)"
)]
struct Args {
    /// NDJSON file to append matches to.
    #[arg(short, long, default_value = "wallets.ndjson")]
    output: PathBuf,

    /// Worker threads (defaults to all available cores).
    #[arg(short, long)]
    threads: Option<usize>,

    /// Suppress the per-second throughput report on stderr.
    #[arg(short, long)]
    quiet: bool,
}

/// Shared, read-mostly state handed to every worker.
struct Shared {
    patterns: PatternSet,
    sink: NdjsonSink,
    attempts: AtomicU64,
    hits: AtomicU64,
    errors: AtomicU64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let threads = args
        .threads
        .or_else(|| thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1);

    let shared = Arc::new(Shared {
        patterns: PatternSet::compiled()?,
        sink: NdjsonSink::appending(&args.output)?,
        attempts: AtomicU64::new(0),
        hits: AtomicU64::new(0),
        errors: AtomicU64::new(0),
    });

    eprintln!(
        "⛏  mining on {threads} threads → {} (path {}). Ctrl-C to stop.",
        args.output.display(),
        wallet::DERIVATION_PATH
    );

    if !args.quiet {
        spawn_reporter(Arc::clone(&shared));
    }

    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let shared = Arc::clone(&shared);
            thread::spawn(move || mine(&shared))
        })
        .collect();

    // Workers loop forever; joining just parks main until Ctrl-C.
    workers.into_iter().try_for_each(|handle| {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("worker panicked"))?
    })
}

/// One worker: build per-thread crypto context + CSPRNG, then mine forever.
fn mine(shared: &Shared) -> Result<()> {
    let secp = Secp256k1::new();
    let path = wallet::derivation_path()?;
    // ChaCha CSPRNG seeded from OS entropy once — secure draws, no per-iteration syscall.
    let mut rng = StdRng::from_entropy();
    loop {
        match Wallet::generated(&mut rng, &secp, &path) {
            Ok(w) => record_if_beautiful(shared, &w),
            Err(_) => {
                shared.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        shared.attempts.fetch_add(1, Ordering::Relaxed);
    }
}

/// Append the wallet iff its address matches a pattern. BTC is derived here,
/// lazily, so the cost is paid only on the rare hit.
fn record_if_beautiful(shared: &Shared, wallet: &Wallet) {
    let Some(pattern) = shared.patterns.matched(&wallet.ethereum_address) else {
        return;
    };
    let record = Record {
        mnemonic_phrase: &wallet.mnemonic_phrase,
        private_key: &wallet.private_key_hex(),
        bitcoin_address: &wallet.bitcoin_address(),
        ethereum_address: &wallet.ethereum_address,
        description: pattern.description,
    };
    match shared.sink.append(&record) {
        Ok(()) => {
            shared.hits.fetch_add(1, Ordering::Relaxed);
            eprintln!("✨ {}  {}", wallet.ethereum_address, pattern.description);
        }
        Err(error) => eprintln!("⚠️  failed to write match: {error:#}"),
    }
}

/// Print attempts/sec, total hits, and error count once per second.
fn spawn_reporter(shared: Arc<Shared>) {
    thread::spawn(move || {
        let mut previous = 0u64;
        loop {
            thread::sleep(Duration::from_secs(1));
            let attempts = shared.attempts.load(Ordering::Relaxed);
            let rate = attempts.saturating_sub(previous);
            previous = attempts;
            eprintln!(
                "   {attempts:>14} tried  {rate:>10}/s  hits {}  errors {}",
                shared.hits.load(Ordering::Relaxed),
                shared.errors.load(Ordering::Relaxed),
            );
        }
    });
}
