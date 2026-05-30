# beautiful-wallet (Rust)

[![lang](https://img.shields.io/badge/lang-Rust-orange)](https://www.rust-lang.org/) [![port of](https://img.shields.io/badge/port%20of-GeneralD%2Fbeautiful--wallet-blue)](https://github.com/GeneralD/beautiful-wallet) [![chain](https://img.shields.io/badge/chain-Ethereum%20%2B%20Bitcoin-blue)](https://ethereum.org/) [![speedup](https://img.shields.io/badge/vs%20TS-~20x-green)](#benchmarks) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A fast, parallel **vanity BIP39 wallet miner** — a Rust port of the TypeScript
[`GeneralD/beautiful-wallet`](https://github.com/GeneralD/beautiful-wallet).

It generates fresh BIP39 wallets, derives the standard Ethereum account
(`m/44'/60'/0'/0/0`), and appends every wallet whose address matches a "beautiful"
pattern (repeated digits, leading runs, ascending sequences, …) to an NDJSON file.

> The browser/front-end half of the original (`src/front/**`, `public/**`) is
> intentionally **not** ported — this is the mining core only.

## What it produces

Each generated wallet runs through the exact same pipeline as the original:

```
32 bytes entropy
  → 24-word BIP39 mnemonic
  → seed  (PBKDF2-HMAC-SHA512, 2048 rounds)
  → BIP32 derive  m/44'/60'/0'/0/0
  → Ethereum address (Keccak-256 + EIP-55 checksum)  ┐ matched against patterns
  → Bitcoin  address (legacy P2PKH, Base58Check)     ┘ written only for hits
```

Matches are appended to `wallets.ndjson`, one JSON object per line:

```json
{"mnemonicPhrase":"...","privateKey":"...","bitcoinAddress":"1...","ethereumAddress":"0x...","description":"starts with 7 sevens"}
```

Field names mirror the original CSV columns; NDJSON replaces CSV so an
interrupted run never leaves a torn final record and output streams line-by-line.

## Usage

```shell
cargo build --release

# Mine on all cores, append matches to wallets.ndjson, Ctrl-C to stop
./target/release/beautiful-wallet

# Options
./target/release/beautiful-wallet --output gems.ndjson --threads 8
./target/release/beautiful-wallet --quiet           # no throughput report
```

```
-o, --output <FILE>    NDJSON file to append matches to [default: wallets.ndjson]
-t, --threads <N>      Worker threads [default: all cores]
-q, --quiet            Suppress the per-second throughput report (stderr)
```

## Benchmarks

Apple M1 Max (8 performance + 2 efficiency cores), release build:

| Build | Throughput | vs original |
|---|---:|---:|
| TypeScript original (`ts-node`, single-thread) | ~275 wallets/s | 1× |
| Rust, single thread | ~1,300 wallets/s | ~4.7× |
| Rust, all cores | ~5,000–6,300 wallets/s | **~18–23×** |

Where the speed comes from, in order of impact:

1. **Parallelism.** The search is embarrassingly parallel — one independent
   infinite loop per core.
2. **Hardware SHA-512.** Each iteration is dominated by PBKDF2-HMAC-SHA512
   (2048 rounds); seed derivation uses [`ring`](https://crates.io/crates/ring)'s
   hand-tuned aarch64 assembly rather than a software hash (~1.8× per thread).
3. **No wasted work.** The original computes a Bitcoin address *every* iteration
   but only ever matches on the Ethereum address — here BTC is derived lazily,
   only for hits. The per-iteration `console.log` (a real multi-core stdout
   bottleneck) is replaced by a single once-per-second reporter.

PBKDF2 is an intentional cost of BIP39 and is the hard floor on per-iteration
speed — the pattern check is negligible by comparison. Sustained all-core rates
fluctuate with thermal throttling on a laptop.

## Patterns

The full pattern set from the original is ported verbatim (39 patterns,
38 distinct descriptions — the two ascending-alphabet variants share a label:
"only numbers", "starts with 7 sevens", "includes 8 zeros", "multiple of 3",
ascending sequences, …). Patterns are matched against the **EIP-55 checksummed**
address, preserving the original's per-pattern case sensitivity, and the first
match in declaration order names the hit.

## Correctness

Derivation parity with the reference `wallet.ts` library is locked by tests:
fixed-entropy vectors (mnemonic, private key, EIP-55 address, P2PKH address) were
captured from `wallet.ts` itself and asserted in `cargo test`. Any divergence in
Keccak-vs-SHA3, EIP-55 casing, compressed-vs-uncompressed public key, or the
BIP32 path fails the suite.

```shell
cargo test
```

## Security

- **Entropy is cryptographically secure.** Each worker seeds a ChaCha CSPRNG
  (`StdRng`) from OS entropy once, then draws 32-byte seeds from it — secure, but
  without a `getentropy` syscall per iteration. **Never** replace this with a
  non-CSPRNG: weak entropy makes generated funds guessable (cf. the `profanity`
  key-space vulnerability).
- **Generated mnemonics and private keys are secrets.** Mine offline, treat
  `wallets.ndjson` as sensitive, and delete every wallet you don't keep.

## License

MIT — see [LICENSE](LICENSE).
