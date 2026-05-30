//! Address encoders for the public key derived at `m/44'/60'/0'/0/0`.
//!
//! Faithful to `wallet.ts`:
//! - Ethereum: Keccak-256 of the uncompressed public key (prefix byte dropped),
//!   last 20 bytes, rendered with the EIP-55 mixed-case checksum.
//! - Bitcoin: legacy P2PKH (Base58Check) of the *compressed* public key.

use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 (Ethereum's hash — *not* SHA3-256; the padding differs).
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// The raw 20-byte Ethereum address (no checksum, no `0x`).
fn eth_address_bytes(public_key: &PublicKey) -> [u8; 20] {
    let uncompressed = public_key.serialize_uncompressed(); // 65 bytes, [0] == 0x04
    let hashed = keccak256(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hashed[12..]);
    address
}

/// EIP-55 checksummed Ethereum address, `0x`-prefixed and mixed-case.
pub fn ethereum_address(public_key: &PublicKey) -> String {
    let address = eth_address_bytes(public_key);
    let lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    // The checksum hashes the lowercase *hex ASCII string* (without `0x`).
    let hash = keccak256(lower.as_bytes());
    let checksummed: String = lower
        .char_indices()
        .map(|(i, c)| {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            match c.is_ascii_hexdigit() && c.is_alphabetic() && nibble >= 8 {
                true => c.to_ascii_uppercase(),
                false => c,
            }
        })
        .collect();
    format!("0x{checksummed}")
}

/// Legacy P2PKH (Base58Check, version `0x00`) of the compressed public key.
pub fn bitcoin_address(public_key: &PublicKey) -> String {
    let compressed = public_key.serialize(); // 33 bytes
    let sha = Sha256::digest(compressed);
    let ripe = Ripemd160::digest(sha);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00); // mainnet P2PKH version
    payload.extend_from_slice(&ripe);
    bs58::encode(payload).with_check().into_string()
}
