//! `normalizeForTag` — canonical normalization for the content-dedup fingerprint.
//! Mirrors `src/lib/text.js` exactly:
//!
//! ```text
//! NFKC → toLowerCase → collapse /\s+/ → strip /\p{Cc}/ → trim
//!      → strip trailing /[\p{P}]+/ → trim
//! ```
//!
//! ## Unicode-version reconciliation (SUR-716; anchor = V8/Node Unicode 17.0)
//!
//! - **NFKC** → `unicode-normalization` 0.1.25 = Unicode **17.0** ✓ (matches anchor).
//! - **toLowerCase** → std `str::to_lowercase` = Unicode **17.0**, full SpecialCasing
//!   incl. the Greek final-sigma rule, matching JS `String.prototype.toLowerCase`.
//! - **`\p{Cc}`** → std `char::is_control` = Unicode **17.0** ✓ (Cc is also extremely
//!   stable across versions).
//! - **`\p{P}` / `\p{Zs}`** → `unicode-general-category` 1.1.0 = Unicode **16.0**.
//!   No real-tables General_Category crate is at 17.0 yet (`regex-syntax` is also 16.0),
//!   so this is the single residual skew vs the anchor: a codepoint whose P/Zs
//!   membership *changes* in 17.0 would diverge. None of the parity vectors hit that;
//!   the B6 differential fuzz characterizes the residue. Using real tables (not the
//!   spike's hand-coded ranges) closes the crypto-reviewer "real tables" condition.

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

pub fn normalize_for_tag(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let nfkc: String = text.nfkc().collect();
    let lower = nfkc.to_lowercase();
    let collapsed = collapse_whitespace(&lower);
    // Strip /\p{Cc}/ AFTER whitespace collapse, so tab/newline (which are both \s and
    // Cc) become a real space boundary first and only the non-whitespace controls
    // (NUL, BEL, …) are removed — matching the JS ordering.
    let no_ctrl: String = collapsed.chars().filter(|c| !c.is_control()).collect();
    let trimmed = no_ctrl.trim();
    let stripped = trimmed.trim_end_matches(is_punctuation);
    stripped.trim().to_string()
}

/// `/\s+/g` → single U+0020, matching ECMAScript `\s` EXACTLY — not Rust
/// `char::is_whitespace`, which differs at U+0085 (NEL, whitespace in Rust but not ES)
/// and U+FEFF (ES whitespace but not Rust). ES `\s` = Space_Separator (Zs) ∪
/// {TAB, LF, VT, FF, CR, SP, NBSP, ZWNBSP/FEFF, LS, PS}.
fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if is_ecmascript_whitespace(c) {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

fn is_ecmascript_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{FEFF}'
            | '\u{2028}'
            | '\u{2029}'
    ) || get_general_category(c) == GeneralCategory::SpaceSeparator
}

/// `\p{P}` = Unicode General_Category Punctuation (Pc, Pd, Pe, Pf, Pi, Po, Ps).
fn is_punctuation(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::ClosePunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::OtherPunctuation
            | GeneralCategory::OpenPunctuation
    )
}

/// Differential fuzz: `normalize_for_tag` (Rust) vs `normalizeForTag` (V8/Node, the JS
/// oracle) over a large, deliberately Unicode-diverse generated corpus. This is the
/// "expand the corpus well beyond 9 vectors / differential-fuzz over a large corpus"
/// crypto-reviewer condition (SUR-716 B6) — continuous breadth on top of the 9 frozen
/// golden vectors that remain the cross-repo contract.
///
/// Requires Node on PATH at the parity anchor (Unicode 17.0 / Node v24.15.0); CI's
/// ubuntu runner has it. Locally without Node the test self-skips rather than failing.
///
/// Fence: the only known irreducible residue is the `\p{P}`/`\p{Zs}` Unicode 16.0↔17.0
/// skew (`unicode-general-category` 1.1.0 is 16.0; the anchor is 17.0). A mismatch is
/// fenced iff its input contains a codepoint that 16.0 leaves Unassigned — i.e. one V8's
/// 17.0 tables may categorize but ours cannot yet. Any mismatch NOT explained that way
/// is a real divergence and fails the test.
#[cfg(test)]
mod differential_fuzz {
    use super::{get_general_category, normalize_for_tag, GeneralCategory};
    use std::process::Command;

    /// Deterministic xorshift64* — no entropy, no crate, fully reproducible corpus.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u32) -> u32 {
            (self.next_u64() % u64::from(n)) as u32
        }
        fn pick(&mut self, xs: &[u32]) -> u32 {
            xs[self.below(xs.len() as u32) as usize]
        }
    }

    // Whitespace-ish + case-folding hotspots worth hitting deterministically.
    const WS: &[u32] = &[
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x85, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        0xFEFF, 0x1680, 0x2000, 0x200A,
    ];
    const HOTSPOTS: &[u32] = &[
        0x03A3, 0x03C2, 0x00DF, 0x1E9E, 0x0130, 0x0131, 0xFB00, 0xFB01, 0xFB02, 0x1F80, 0x0049,
    ];

    fn random_char(rng: &mut Rng) -> char {
        loop {
            let cp = match rng.below(13) {
                0 => rng.below(0x80),               // ASCII
                1 => rng.below(0x20),               // C0 control
                2 => 0x80 + rng.below(0x80),        // C1 / Latin-1 supplement
                3 => rng.pick(WS),                  // whitespace family
                4 => 0x300 + rng.below(0x70),       // combining marks
                5 => 0xFF00 + rng.below(0xF0),      // full/half-width forms
                6 => 0x2000 + rng.below(0x70),      // general punctuation (dashes, quotes, …)
                7 => 0x3000 + rng.below(0x40),      // CJK symbols & punctuation
                8 => rng.pick(HOTSPOTS),            // case-fold hotspots (Σ ς ß ẞ İ ı ﬀ …)
                9 => 0x4E00 + rng.below(0x200),     // CJK ideographs
                10 => rng.below(0x10000),           // any BMP scalar
                11 => 0x10000 + rng.below(0xF0000), // astral (emoji, new-plane assignments)
                _ => 0xE000 + rng.below(0x1900),    // PUA + nearby
            };
            if let Some(c) = char::from_u32(cp) {
                return c;
            }
        }
    }

    /// True if the mismatch is attributable to the documented 16.0↔17.0 General_Category
    /// skew — the input carries a codepoint our 16.0 tables leave Unassigned.
    fn is_fenced_residue(input: &str) -> bool {
        input
            .chars()
            .any(|c| get_general_category(c) == GeneralCategory::Unassigned)
    }

    /// The V8 oracle must run at the parity anchor (Unicode 17.0). Returns `false`
    /// (skip) if Node is absent or lags — CI pins v24.15.0 and verifies the anchor in a
    /// prior workflow step, so this never silently skips there.
    fn node_is_anchor() -> bool {
        match Command::new("node")
            .args(["-p", "process.versions.unicode"])
            .output()
        {
            Ok(o) if o.status.success() => {
                let uni = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if uni == "17.0" {
                    return true;
                }
                eprintln!("SKIP: node Unicode is {uni}, the anchor is 17.0 (use Node v24.15.0)");
                false
            }
            _ => {
                eprintln!(
                    "SKIP: `node` not on PATH — the differential fuzz needs Node (CI has it)"
                );
                false
            }
        }
    }

    #[test]
    fn rust_matches_v8_over_large_corpus() {
        if !node_is_anchor() {
            return;
        }
        const N: usize = 20_000;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let corpus: Vec<String> = (0..N)
            .map(|_| {
                let len = rng.below(10);
                (0..len).map(|_| random_char(&mut rng)).collect()
            })
            .collect();

        let oracle = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/normalize_oracle.mjs");
        let corpus_path = std::env::temp_dir().join("braird_normalize_corpus.json");
        std::fs::write(&corpus_path, serde_json::to_vec(&corpus).unwrap()).unwrap();

        let output = match Command::new("node").arg(oracle).arg(&corpus_path).output() {
            Ok(o) => o,
            Err(_) => {
                eprintln!(
                    "SKIP: `node` not on PATH — the differential fuzz needs Node (CI has it)"
                );
                return;
            }
        };
        assert!(
            output.status.success(),
            "node oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), corpus.len(), "oracle returned wrong count");

        let mut fenced = 0usize;
        let mut unfenced: Vec<(String, String, String)> = Vec::new();
        for (input, want) in corpus.iter().zip(&expected) {
            let got = normalize_for_tag(input);
            if &got != want {
                if is_fenced_residue(input) {
                    fenced += 1;
                } else {
                    unfenced.push((input.clone(), got, want.clone()));
                }
            }
        }

        eprintln!(
            "differential fuzz: {N} inputs · {fenced} fenced (Unicode 16↔17 \\p{{P}}/\\p{{Zs}} residue on 16.0-unassigned codepoints) · {} unfenced",
            unfenced.len()
        );
        assert!(
            unfenced.is_empty(),
            "unfenced Rust↔V8 normalization mismatches (showing up to 12): {:#?}",
            &unfenced[..unfenced.len().min(12)]
        );
    }
}
