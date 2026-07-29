//! Hybrid lexical + semantic rank fusion (SUR-1019, ADR 0007) — the platform-neutral
//! ranking leg of SUR-157. Combines the MiniSearch-parity lexical ranking (`search`,
//! ADR 0005) and the sealed-vector cosine scan (`embeddings`, ADR 0006) into ONE ranked
//! answer, in core, so the two native surfaces cannot drift on ranking.
//!
//! ## Why reciprocal rank fusion and not score blending
//!
//! The two engines' scores share no unit: lexical scores are unbounded above (they grow
//! with query-term count via the `matched` multiplier), cosine lives in `[-1, 1]`. ADR 0006
//! recorded exactly this trap ("blend knowingly, never sum naively"). RRF fuses **ranks**,
//! not scores — `score = Σ 1/(k + rank)` over the lists a document appears in — so no
//! cross-scale calibration exists to get wrong, and a document surfacing in both lists
//! outranks one of equal rank in a single list, which is the behaviour hybrid search wants.
//! `k = 60` is the literature-standard damping constant (Cormack et al.); it and the floor
//! below are **core constants, not host config** — hosts drifting on ranking policy is the
//! failure mode this module exists to prevent.
//!
//! ## The relevance floor
//!
//! A brute-force cosine scan is a pure top-k: it always returns the least-bad vectors, and
//! at personal-archive scale "least bad" is routinely garbage. [`SEMANTIC_FLOOR`] defines
//! "no good semantic match": scan hits below it never enter fusion, and when NONE survive
//! the caller reports [`SemanticStatus::NoSemanticMatch`] so surfaces can say *nothing here
//! matched by meaning* instead of padding the list.
//!
//! This module is the pure half (fusion math + the FFI result types, unit-testable on fixed
//! rankings); the choreography — corpus build, the foreign `embed_query` call, the scan,
//! hydration — lives on `SyncEngine::ranked_search` in `sync/mod.rs`, where the locks live.

use std::collections::HashMap;

use crate::embeddings::SemanticHit;
use crate::search::{SearchDocKind, SearchHit};

/// RRF's rank-damping constant: contribution = `1/(k + rank)`. 60 is the original
/// TREC-validated default; at that damping a #1 rank contributes ~1.6× a #10 rank, gentle
/// enough that agreement across both lists dominates single-list rank differences.
pub(crate) const RRF_K: f64 = 60.0;

/// The cosine floor that defines "no good semantic match" (inclusive: a hit AT the floor
/// survives). Scan hits below it are discarded before fusion.
///
/// **Measured, not guessed** (SUR-1019 step 8a, 2026-07-29). Derived on a Galaxy S25U
/// (SM-S938B) running the real EmbeddingGemma-300M-qat-seq256 through LiteRT — the value is
/// a property of THAT model's geometry (prompt-conditioned, Matryoshka-truncated to 256
/// dims), so it is only meaningful against that descriptor. 432 labeled query×document
/// cosines over an 18-note calibration corpus:
///
/// | band                                   |   n |  p50   |  max   |
/// |----------------------------------------|-----|--------|--------|
/// | related (paraphrase, low word overlap) |  18 | 0.5347 | 0.7273 |
/// | tangential (same subject, other idea)  |  36 | 0.3901 | 0.5618 |
/// | unrelated (different subject)          | 270 | 0.3024 | 0.5243 |
/// | nonsense (absent from the corpus)      | 108 | 0.1367 | 0.3245 |
///
/// The decisive band is `nonsense` — the floor exists so a search for something the archive
/// does not contain reports [`SemanticStatus::NoSemanticMatch`] rather than the least-bad
/// vector. Its ceiling (0.3245) and the lowest related score (0.3818) leave a clean interval
/// of `(0.3245, 0.3818]`, every value of which admits **zero** nonsense hits and keeps
/// **all** related ones. 0.35 is essentially its midpoint (0.3532): +0.0255 of headroom above
/// the noise ceiling, 0.0318 of slack below the weakest true match — the max-margin choice,
/// so drift in either direction has to be substantial before it changes a verdict.
///
/// Known limits of the calibration, so nobody over-trusts it: the related band is only 18
/// samples, so its low tail is the weakly characterised side (hence not pushing the floor
/// higher, where recall is the expensive failure); the corpus is aphoristic 1–3 sentence
/// highlights, the commonplace-book shape, not long-form notes; and queries are natural
/// language, which the model's query template expects — a terse keyword query may score
/// lower and fall below the floor, which is safe here only because RRF still returns the
/// lexical half for exactly that kind of query. Re-run the harness on any descriptor change:
/// a new model, new quantization, or a different Matryoshka width re-keys the corpus AND
/// invalidates this number.
/// TUNE(SUR-1019 step 8a): provisional pending the device pass against the real
/// EmbeddingGemma corpus — the model is prompt-conditioned and Matryoshka-truncated to
/// 256-dim, both of which compress the cosine band, so the release gate re-derives this
/// value from measured related/unrelated query distributions before v0.14.0 ships.
pub(crate) const SEMANTIC_FLOOR: f64 = 0.35;

/// One fused search result. The shape of [`SearchHit`] (same `kind`/`ref_id`/`title`/
/// `snippet` display fields, hydrated from the same decrypted corpus) plus the fusion
/// verdict: `score` is the reciprocal-rank-fusion (RRF) score — the per-engine raw scores are
/// deliberately NOT exposed, because they are incomparable across engines (ADR 0006) and
/// any host arithmetic over them would rebuild the drift this API removes. The two
/// `matched_*` flags say which engine(s) surfaced the hit (for a "matched by meaning"
/// badge); ideas are never in the vector corpus, so an Idea hit always has
/// `matched_semantic == false`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RankedHit {
    pub kind: SearchDocKind,
    pub ref_id: String,
    pub title: String,
    pub snippet: String,
    pub score: f64,
    pub matched_lexical: bool,
    pub matched_semantic: bool,
}

/// What the semantic half of a [`SyncEngine::ranked_search`] call did — a first-class,
/// nameable outcome (SUR-1019 item 4), NOT an error: the lexical half always runs, so a
/// page is always returned and this enum says how to read it. Only store failures error.
///
/// [`SyncEngine::ranked_search`]: crate::sync::SyncEngine::ranked_search
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SemanticStatus {
    /// The scan ran and at least one hit cleared the relevance floor — the ranking is
    /// genuinely hybrid. Also the neutral status of an empty-query / `limit == 0` page
    /// (with an embedder registered): nothing was scanned and nothing was excluded, so
    /// there is no absence to name — drive "matched by meaning" badges off individual
    /// hits' `matched_semantic`, not off this variant alone.
    Fused,
    /// The scan ran but nothing cleared the floor: *nothing here matched by meaning*.
    /// Distinguish "the corpus is still backfilling" via
    /// [`RankedSearchPage::pending_embed_count`].
    NoSemanticMatch,
    /// No embedder is registered (model not downloaded / feature off) — lexical-only page.
    EmbedderNotRegistered,
    /// The registered embedder failed the query embed (host error, wrong dimension,
    /// degenerate vector) — lexical-only page. Often transient (the next call retries),
    /// though a wrong-dimension embedder fails identically every call.
    EmbedderFailed,
}

/// One `ranked_search` answer: the fused hits, how the semantic half fared, and the
/// partial-corpus honesty signal — `pending_embed_count` is the derived embed queue's
/// size (the same number [`SyncEngine::pending_embed_count`] reports, and truthful even
/// on the empty-query guard page; `0` when no embedder is registered, where that method
/// would error), so a surface can say "still indexing N notes" instead of quietly
/// under-returning (SUR-1019 item 5).
///
/// [`SyncEngine::pending_embed_count`]: crate::sync::SyncEngine::pending_embed_count
#[derive(Debug, Clone, uniffi::Record)]
pub struct RankedSearchPage {
    pub hits: Vec<RankedHit>,
    pub semantic_status: SemanticStatus,
    pub pending_embed_count: u32,
}

/// A fused ranking entry before hydration — fusion works on identities + ranks only;
/// display fields are joined back from the decrypted corpus by the caller.
pub(crate) struct Fused {
    pub kind: SearchDocKind,
    pub ref_id: String,
    pub score: f64,
    pub matched_lexical: bool,
    pub matched_semantic: bool,
}

/// Drop scan hits below the relevance floor (inclusive at the boundary). The scan input is
/// best-first and `retain` preserves order, so the output is still a ranking.
pub(crate) fn above_floor(mut hits: Vec<SemanticHit>) -> Vec<SemanticHit> {
    hits.retain(|h| h.score >= SEMANTIC_FLOOR);
    hits
}

/// Reciprocal rank fusion over the two engines' FULL rankings (both engines score their
/// whole corpus and truncate last, so pass them untruncated — a candidate-pool cutoff
/// would just reintroduce rank noise). Returns the complete fused ranking, best-first;
/// the caller truncates after hydration. Deterministic: score descending, then `ref_id`,
/// then kind — total order, so fixed inputs give one fixed output (the property the
/// cross-platform fixtures pin).
///
/// Identity is `(kind, ref_id)`; semantic hits are notes by construction. A document in
/// both lists sums both contributions — that agreement bonus is RRF's whole mechanism.
pub(crate) fn fuse(lexical: &[SearchHit], semantic: &[SemanticHit]) -> Vec<Fused> {
    let rrf = |rank0: usize| 1.0 / (RRF_K + (rank0 + 1) as f64);
    let blank = |kind: SearchDocKind, ref_id: &str| Fused {
        kind,
        ref_id: ref_id.to_string(),
        score: 0.0,
        matched_lexical: false,
        matched_semantic: false,
    };

    let mut by_key: HashMap<(SearchDocKind, String), Fused> = HashMap::new();
    for (rank0, hit) in lexical.iter().enumerate() {
        let e = by_key
            .entry((hit.kind, hit.ref_id.clone()))
            .or_insert_with(|| blank(hit.kind, &hit.ref_id));
        e.score += rrf(rank0);
        e.matched_lexical = true;
    }
    for (rank0, hit) in semantic.iter().enumerate() {
        let e = by_key
            .entry((SearchDocKind::Note, hit.note_id.clone()))
            .or_insert_with(|| blank(SearchDocKind::Note, &hit.note_id));
        e.score += rrf(rank0);
        e.matched_semantic = true;
    }

    // The sort's total order (no two entries share (kind, ref_id)) makes the map's
    // iteration order irrelevant — fixed inputs, fixed output.
    let mut fused: Vec<Fused> = by_key.into_values().collect();
    fused.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.ref_id.cmp(&b.ref_id))
            .then_with(|| kind_order(a.kind).cmp(&kind_order(b.kind)))
    });
    fused
}

/// Tiebreak order for [`SearchDocKind`] (notes before ideas — the corpus insertion order
/// the lexical engine's stable sort already exhibits).
fn kind_order(kind: SearchDocKind) -> u8 {
    match kind {
        SearchDocKind::Note => 0,
        SearchDocKind::Idea => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(kind: SearchDocKind, id: &str, score: f64) -> SearchHit {
        SearchHit {
            kind,
            ref_id: id.into(),
            title: String::new(),
            snippet: String::new(),
            score,
        }
    }
    fn sem(id: &str, score: f64) -> SemanticHit {
        SemanticHit {
            note_id: id.into(),
            score,
        }
    }
    fn ids(fused: &[Fused]) -> Vec<&str> {
        fused.iter().map(|f| f.ref_id.as_str()).collect()
    }

    #[test]
    fn fixed_rankings_fuse_deterministically() {
        let lexical = vec![
            lex(SearchDocKind::Note, "a", 9.0),
            lex(SearchDocKind::Note, "b", 5.0),
            lex(SearchDocKind::Idea, "i", 2.0),
        ];
        let semantic = vec![sem("b", 0.9), sem("c", 0.8)];
        let once = fuse(&lexical, &semantic);
        let twice = fuse(&lexical, &semantic);
        assert_eq!(ids(&once), ids(&twice), "same inputs, same output");
        // "b" appears in both lists (lexical #2 + semantic #1) and beats the single-list
        // #1s: 1/62 + 1/61 > 1/61.
        assert_eq!(ids(&once), vec!["b", "a", "c", "i"]);
    }

    #[test]
    fn both_list_membership_outranks_an_equal_single_list_rank() {
        // "x": lexical #1 + semantic #2. "y": semantic #1 only. Agreement wins.
        let lexical = vec![lex(SearchDocKind::Note, "x", 4.0)];
        let semantic = vec![sem("y", 0.99), sem("x", 0.5)];
        let fused = fuse(&lexical, &semantic);
        // x: 1/61 + 1/62 ≈ 0.0325 > y: 1/61 ≈ 0.0164.
        assert_eq!(ids(&fused), vec!["x", "y"]);
        let x = &fused[0];
        assert!(x.matched_lexical && x.matched_semantic);
        let y = &fused[1];
        assert!(!y.matched_lexical && y.matched_semantic);
    }

    #[test]
    fn an_idea_participates_through_its_lexical_rank_alone() {
        let lexical = vec![
            lex(SearchDocKind::Idea, "idea1", 8.0),
            lex(SearchDocKind::Note, "n1", 3.0),
        ];
        let semantic = vec![sem("n2", 0.7)];
        let fused = fuse(&lexical, &semantic);
        // idea1 (lexical #1) and n2 (semantic #1) tie at 1/61 — ref_id breaks it.
        assert_eq!(ids(&fused), vec!["idea1", "n2", "n1"]);
        let idea = &fused[0];
        assert_eq!(idea.kind, SearchDocKind::Idea);
        assert!(idea.matched_lexical && !idea.matched_semantic);
    }

    #[test]
    fn equal_scores_break_on_ref_id_for_determinism() {
        // Two docs each appearing only at the same rank of one list: identical RRF scores.
        let lexical = vec![lex(SearchDocKind::Note, "zzz", 1.0)];
        let semantic = vec![sem("aaa", 0.9)];
        let fused = fuse(&lexical, &semantic);
        assert_eq!(ids(&fused), vec!["aaa", "zzz"], "ref_id ascending on ties");
    }

    #[test]
    fn empty_inputs_fuse_to_empty_or_pass_through() {
        assert!(fuse(&[], &[]).is_empty());
        // Semantic empty → the lexical ranking passes through in order.
        let lexical = vec![
            lex(SearchDocKind::Note, "a", 9.0),
            lex(SearchDocKind::Note, "b", 5.0),
        ];
        assert_eq!(ids(&fuse(&lexical, &[])), vec!["a", "b"]);
        // Lexical empty → the semantic ranking passes through.
        let semantic = vec![sem("c", 0.9), sem("d", 0.5)];
        assert_eq!(ids(&fuse(&[], &semantic)), vec!["c", "d"]);
    }

    #[test]
    fn the_floor_is_inclusive_at_the_boundary() {
        let hits = vec![
            sem("at", SEMANTIC_FLOOR),
            sem("above", SEMANTIC_FLOOR + 0.1),
            sem("below", SEMANTIC_FLOOR - 1e-9),
            sem("way-below", -0.2),
        ];
        let kept = above_floor(hits);
        let kept_ids: Vec<&str> = kept.iter().map(|h| h.note_id.as_str()).collect();
        assert_eq!(
            kept_ids,
            vec!["at", "above"],
            "≥ floor survives, < floor dies"
        );
    }
}
