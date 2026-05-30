//! Vanity patterns, a faithful port of `BeautifulWallet.ts` + `exec/beautifulWallet.ts`.
//!
//! Each pattern is a regex tested against the EIP-55 *checksummed* (mixed-case)
//! `0x`-prefixed address — exactly what the original matches `wallet.ethereumAddress`
//! against. Per-pattern case sensitivity is preserved: patterns the original wrote
//! with the JS `/i` flag get a `(?i)` prefix here; the three ascendant patterns
//! were case-sensitive in the original and stay so (they are real EIP-55 constraints).
//!
//! `matched()` returns the *first* matching pattern in declaration order, mirroring
//! `Array.prototype.find`, so the reported description is order-deterministic.

use anyhow::{Context, Result};
use regex::Regex;

pub struct Pattern {
    regex: Regex,
    pub description: &'static str,
}

pub struct PatternSet {
    patterns: Vec<Pattern>,
}

impl PatternSet {
    /// Compile the full set once. Shared across threads (regexes are `Sync`).
    pub fn compiled() -> Result<Self> {
        let patterns = SPECS
            .iter()
            .map(|&(source, ci, description)| {
                let pattern = match ci {
                    true => format!("(?i){source}"),
                    false => source.to_string(),
                };
                Regex::new(&pattern)
                    .with_context(|| format!("compile pattern {source:?}"))
                    .map(|regex| Pattern { regex, description })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { patterns })
    }

    /// First matching pattern for the checksummed `0x…` address, or `None`.
    pub fn matched(&self, checksummed_address: &str) -> Option<&Pattern> {
        self.patterns
            .iter()
            .find(|p| p.regex.is_match(checksummed_address))
    }
}

/// `(regex_source, case_insensitive, description)`.
///
/// `case_insensitive == true` reproduces the original JS `/…/i` flag.
/// The regex is applied to the `0x`-prefixed checksummed string, so anchors
/// (`^`) and the `0x` prefix behave identically to the TypeScript version.
#[rustfmt::skip]
const SPECS: &[(&str, bool, &str)] = &[
    (r"^0x\d{40}$",                true,  "only numbers"),
    (r"^0x[a-f]{40}$",             true,  "only alphabets"),
    (r"^0x0{7}",                   true,  "starts with 7 zeros"),
    (r"^0x1{7}",                   true,  "starts with 7 ones"),
    (r"^0x2{7}",                   true,  "starts with 7 twos"),
    (r"^0x3{7}",                   true,  "starts with 7 threes"),
    (r"^0x4{7}",                   true,  "starts with 7 fours"),
    (r"^0x5{7}",                   true,  "starts with 7 fives"),
    (r"^0x6{7}",                   true,  "starts with 7 sixes"),
    (r"^0x7{7}",                   true,  "starts with 7 sevens"),
    (r"^0x8{7}",                   true,  "starts with 7 eights"),
    (r"^0x9{7}",                   true,  "starts with 7 nines"),
    (r"^0xa{7}",                   true,  "starts with 7 a"),
    (r"^0xb{7}",                   true,  "starts with 7 b"),
    (r"^0xc{7}",                   true,  "starts with 7 c"),
    (r"^0xd{7}",                   true,  "starts with 7 d"),
    (r"^0xe{7}",                   true,  "starts with 7 e"),
    (r"^0xf{7}",                   true,  "starts with 7 f"),
    (r"^0x0000[0-9a-f]{32}0000$",  true,  "lead and tail are 4 zeros"),
    (r"^0x[0369a-f]{40}$",         true,  "multiple of 3"),
    (r"^0x0123456",                false, "starts with number ascendant"),
    (r"^0xabcdef",                 false, "starts with alphabet ascendant"),
    (r"^0xABCDEF",                 false, "starts with alphabet ascendant"),
    (r"0{8}",                      true,  "includes 8 zeros"),
    (r"1{8}",                      true,  "includes 8 ones"),
    (r"2{8}",                      true,  "includes 8 twos"),
    (r"3{8}",                      true,  "includes 8 threes"),
    (r"4{8}",                      true,  "includes 8 fours"),
    (r"5{8}",                      true,  "includes 8 fives"),
    (r"6{8}",                      true,  "includes 8 sixes"),
    (r"7{8}",                      true,  "includes 8 sevens"),
    (r"8{8}",                      true,  "includes 8 eights"),
    (r"9{8}",                      true,  "includes 8 nines"),
    (r"a{8}",                      true,  "includes 8 a"),
    (r"b{8}",                      true,  "includes 8 b"),
    (r"c{8}",                      true,  "includes 8 c"),
    (r"d{8}",                      true,  "includes 8 d"),
    (r"e{8}",                      true,  "includes 8 e"),
    (r"f{8}",                      true,  "includes 8 f"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_match_wins_in_declaration_order() -> Result<()> {
        let set = PatternSet::compiled()?;
        // Starts with 7 zeros → also "includes 8 zeros" via the "0x" + 7 zeros?
        // No: the 'x' breaks the run, so this only hits "starts with 7 zeros",
        // which is declared first regardless.
        let m = set
            .matched("0x0000000abcdef0123456789012345678901234ab")
            .map(|p| p.description);
        assert_eq!(m, Some("starts with 7 zeros"));
        Ok(())
    }

    #[test]
    fn ascendant_patterns_are_case_sensitive() -> Result<()> {
        let set = PatternSet::compiled()?;
        // Lowercase ascendant matches the case-sensitive `^0xabcdef`.
        assert_eq!(
            set.matched("0xabcdef0123456789012345678901234567890123")
                .map(|p| p.description),
            Some("starts with alphabet ascendant"),
        );
        // EIP-55 never yields a leading "0xABCDEF" run with this body, but the
        // pattern must accept it when it does (uppercase variant).
        assert_eq!(
            set.matched("0xABCDEF0123456789012345678901234567890123")
                .map(|p| p.description),
            Some("starts with alphabet ascendant"),
        );
        Ok(())
    }

    #[test]
    fn plain_address_does_not_match() -> Result<()> {
        let set = PatternSet::compiled()?;
        assert!(
            set.matched("0x1234aB5678cD9012eF3456789012aB34567890cD")
                .is_none()
        );
        Ok(())
    }
}
