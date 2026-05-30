//! A freshly generated BIP39 wallet, mirroring `CryptoWallet.ts`.
//!
//! Pipeline per wallet (identical derivation to the original):
//! 32 bytes entropy → 24-word mnemonic → seed (PBKDF2-HMAC-SHA512, 2048 rounds)
//! → BIP32 derive `m/44'/60'/0'/0/0` → ETH/BTC addresses + private key.
//!
//! The BTC address is intentionally *not* computed here — matching is done on
//! the Ethereum address only, so BTC is derived lazily for hits (see [`Wallet::bitcoin_address`]).
//! This removes a SHA-256 + RIPEMD-160 + Base58 pass from every non-matching iteration.

use anyhow::{Context, Result};
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use rand::RngCore;
use ring::pbkdf2;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::num::NonZeroU32;
use std::str::FromStr;

use crate::address;

/// Standard Ethereum account path. MetaMask et al. restore this directly.
pub const DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

/// BIP39 stretches the mnemonic with 2048 PBKDF2 rounds.
const PBKDF2_ITERATIONS: NonZeroU32 = match NonZeroU32::new(2048) {
    Some(n) => n,
    None => panic!("BIP39 iteration count is nonzero"),
};

/// Parse the derivation path once per thread (negligible vs PBKDF2, but kept
/// out of the hot loop). Propagates instead of panicking.
pub fn derivation_path() -> Result<DerivationPath> {
    DerivationPath::from_str(DERIVATION_PATH).context("parse derivation path")
}

/// BIP39 seed: `PBKDF2-HMAC-SHA512(phrase, "mnemonic", 2048)` → 64 bytes.
///
/// This is *the* per-iteration bottleneck, so it uses `ring`'s hand-tuned
/// aarch64 SHA-512 assembly instead of the pure-Rust software path. English
/// BIP39 phrases are ASCII, so NFKD normalization is a no-op, and the empty
/// passphrase leaves the salt as the fixed string `"mnemonic"`. Parity with the
/// reference `wallet.ts` seed is locked by [`tests::matches_wallet_ts_vectors`].
fn seed_from_phrase(phrase: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        PBKDF2_ITERATIONS,
        b"mnemonic",
        phrase.as_bytes(),
        &mut seed,
    );
    seed
}

pub struct Wallet {
    pub mnemonic_phrase: String,
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub ethereum_address: String,
}

impl Wallet {
    /// Generate a wallet from fresh entropy drawn from `rng`.
    ///
    /// `rng` must be a **cryptographically secure** generator. The miner seeds
    /// one per thread with [`rand::rngs::StdRng`] (a ChaCha block cipher CSPRNG)
    /// from OS entropy, so each draw is secure but costs no per-iteration
    /// `getentropy` syscall — calling `OsRng` directly in the hot loop serializes
    /// every thread in the kernel. Never swap in a non-CSPRNG: weak entropy makes
    /// generated funds guessable (cf. the `profanity` key-space vulnerability).
    pub fn generated<R: RngCore>(
        rng: &mut R,
        secp: &Secp256k1<secp256k1::All>,
        path: &DerivationPath,
    ) -> Result<Self> {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy, secp, path)
    }

    /// Deterministic construction from fixed entropy — used by parity tests.
    pub fn from_entropy(
        entropy: &[u8; 32],
        secp: &Secp256k1<secp256k1::All>,
        path: &DerivationPath,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::from_entropy(entropy).context("mnemonic from entropy")?;
        let phrase = mnemonic.to_string();
        let seed = seed_from_phrase(&phrase);
        let xprv = XPrv::derive_from_path(seed, path).context("BIP32 derive")?;
        let private_key = SecretKey::from_slice(&xprv.to_bytes()).context("secret key")?;
        let public_key = private_key.public_key(secp);
        let ethereum_address = address::ethereum_address(&public_key);
        Ok(Self {
            mnemonic_phrase: phrase,
            private_key,
            public_key,
            ethereum_address,
        })
    }

    /// Lazily computed Bitcoin P2PKH address (only needed for hits).
    pub fn bitcoin_address(&self) -> String {
        address::bitcoin_address(&self.public_key)
    }

    /// Private key as a 64-char lowercase hex string (no `0x`), matching `wallet.ts`.
    pub fn private_key_hex(&self) -> String {
        self.private_key
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth vectors captured from the actual `wallet.ts` library
    /// (`Mnemonic`/`HDKey`/`EthereumAddress`/`BitcoinAddress`) with fixed
    /// entropy. If any derivation step diverges (Keccak vs SHA3, EIP-55,
    /// compressed vs uncompressed pubkey, BIP32 path), one of these fails.
    struct Vector {
        entropy: [u8; 32],
        mnemonic: &'static str,
        private_key: &'static str,
        ethereum: &'static str,
        bitcoin: &'static str,
    }

    const VECTORS: &[Vector] = &[
        Vector {
            entropy: [0x00; 32],
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            private_key: "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f",
            ethereum: "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb",
            bitcoin: "1MyCC8TjrTfEHC4YrVjpPV6ewGMRd86e7U",
        },
        Vector {
            entropy: [0xff; 32],
            mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            private_key: "105434ca932be16664cb5e44e5b006728577dd757440d068e6d15ef52c15a82f",
            ethereum: "0x1959f5f4979c5Cd87D5CB75c678c770515cb5E0E",
            bitcoin: "17yb3AEws3F8EnkCBA9yJHZJaEVd7qvnnJ",
        },
        Vector {
            entropy: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ],
            mnemonic: "abuse boss fly battle rubber wasp afraid hamster guide essence vibrant task banana pencil owner cube social job emotion member joy sting dash trouble",
            private_key: "0e755f9cf0a30e5903f3c519440553d77175a5c821e9cb48e98268bb1fc54e79",
            ethereum: "0xc1e21cE0902f1AF587557F591302cc561EB20f56",
            bitcoin: "19yThLapscmDP2D7qDWqVAvNWqHxbwqpaF",
        },
    ];

    #[test]
    fn matches_wallet_ts_vectors() -> Result<()> {
        let secp = Secp256k1::new();
        let path = derivation_path()?;
        for v in VECTORS {
            let wallet = Wallet::from_entropy(&v.entropy, &secp, &path)?;
            assert_eq!(wallet.mnemonic_phrase, v.mnemonic, "mnemonic");
            assert_eq!(wallet.private_key_hex(), v.private_key, "private key");
            assert_eq!(wallet.ethereum_address, v.ethereum, "ETH address (EIP-55)");
            assert_eq!(wallet.bitcoin_address(), v.bitcoin, "BTC address (P2PKH)");
        }
        Ok(())
    }
}
