# ADR 0007 — Core-owned hybrid rank fusion (lexical × semantic)

- **Status:** Proposed (SUR-1019; agent under the GCE gate — awaits `sync-reviewer` +
  `crypto-reviewer` + `naming-reviewer` + `architecture-decision-reviewer` + founder sign-off,
  per `GATING.md`). Pressure-tested on the SUR-1019 decomposition record (Linear, 2026-07-29
  comment: six founder decisions).
- **Date:** 2026-07-29
- **Context tickets:** SUR-1019 (this, the core leg of SUR-157). Builds on ADR 0005 (the
  lexical engine + decrypt-in-core read boundary) and ADR 0006 (the sealed vector store +
  cosine scan). **Amends ADR 0006:** its consequence "ranking policy, thresholds, and
  blending stay consumer-side" is superseded — ranking policy now lives in core.
  Consumed by SUR-1020 (Android) / SUR-1021 (iOS) via a pinned release.

## Context

SUR-157 needs ONE ranked answer over two engines core already has: the MiniSearch-parity
lexical `search()` (notes + ideas, in-memory per call) and the brute-force cosine scan over
the sealed vector corpus (notes only). Their scores are incomparable by construction —
lexical relevance is unbounded above and grows with query-term count; cosine lives in
`[-1, 1]` — a trap ADR 0006 recorded and deferred to consumers.

Deferring it further would mean two independent fusion implementations, one per platform.
Ranking drift between them is unfalsifiable from a bug report ("results feel different on my
phone"), and the SUR-998 lane spent a week engineering exactly this class of divergence out
of the embed pipeline. Fusion is therefore core work: the same discipline, one layer up.

## Decision

1. **Reciprocal rank fusion, not score blending.** `score = Σ 1/(k + rank)` over the lists a
   document appears in, `k = 60` (the literature-standard damping). RRF consumes **ranks**,
   so no calibration between the two incomparable scales exists to get wrong; a document
   surfacing in both lists outranks an equal-ranked single-list document, which is the
   agreement bonus hybrid search wants. The constant is core's (`fusion::RRF_K`), not host
   config — configurable ranking would reintroduce the drift this ADR removes.
2. **Both engines contribute their FULL rankings.** Each already scores its whole corpus and
   truncates last, so fusion sees untruncated lists and truncates after — no candidate-pool
   cutoff, no rank noise at a pool boundary. Ideas participate through their lexical rank
   alone (they are never in the vector corpus); identity is `(kind, ref_id)`.
3. **A relevance floor defines "no good semantic match".** The scan is a pure top-k — it
   always returns the least-bad vectors, and at personal-archive scale least-bad is routinely
   noise. Scan hits below `fusion::SEMANTIC_FLOOR` (cosine, inclusive) never enter fusion;
   when none survive, the result names the outcome (`NoSemanticMatch`) so surfaces can say
   *nothing here matched by meaning* instead of padding the list.

   **The value is measured, not chosen** (step 8a, 2026-07-29, before the release cut — the
   constant sits behind release-skew, so a wrong value costs a patch release plus both host
   pin bumps). Method: 432 labeled query×document cosines over an 18-note calibration corpus,
   embedded on a Galaxy S25U through the real EmbeddingGemma-300M-qat-seq256 / LiteRT
   pipeline, in four bands — *related* (paraphrase with deliberately low word overlap, the
   case only semantic search can serve), *tangential*, *unrelated*, and *nonsense* (plausible
   searches for content the archive does not hold). The nonsense band is the decisive one: it
   is precisely what the floor exists to reject, and it is the best-sampled (n=108). Its
   ceiling is 0.3245; the lowest related score is 0.3818. Every value in `(0.3245, 0.3818]`
   therefore admits zero nonsense hits while keeping every related one, and **0.35 is
   effectively that interval's midpoint** (0.3532) — chosen for maximum margin on both sides
   rather than for the number itself. The pre-measurement placeholder happened to be 0.35;
   the calibration confirmed it rather than moved it, which is worth recording so a future
   reader does not mistake a measured value for an unexamined default.

   Where the floor is deliberately biased: within the clean interval the cost of the two
   errors is asymmetric — too high silently guts recall (semantic search stops contributing
   and `NoSemanticMatch` over-fires), too low admits noise that RRF then damps to a low rank
   anyway. The related band is also the smaller sample. Both point the same way, so the floor
   is not pushed toward the recall edge.
4. **One FFI call, degrade-to-status, never degrade-to-error.** `ranked_search(query, limit)
   → RankedSearchPage { hits, semantic_status, pending_embed_count }`. The lexical half
   always answers; every legitimate semantic absence is a nameable `SemanticStatus`
   (`EmbedderNotRegistered`, `EmbedderFailed`, `NoSemanticMatch`) on a lexical-only page —
   an unfused page is a search *outcome*, not a failure. Only store failures error.
   `pending_embed_count` (the derived-queue size, the same number the
   `pending_embed_count()` method reports — except `0` where that method would error on an
   unregistered embedder) is the partial-corpus honesty signal: mid-backfill a surface says
   "still indexing N notes" instead of quietly under-returning. Degenerate queries
   (empty/whitespace, `limit == 0`) return an empty page without the ~0.8 s embed call, but
   the status and pending count are still computed truthfully — hosts initialize
   search-screen state from exactly that call, so the guard must not fake "hybrid ready,
   nothing indexing" (`Fused` doubles as the guard's neutral status only when an embedder
   is registered; its docstring names the vacuous case). Per-engine raw scores are
   deliberately NOT in the result — host arithmetic over them is the drift vector; hosts
   get the fused score plus `matched_lexical`/`matched_semantic`.
5. **Choreography follows the established seams.** The lexical corpus builds under the store
   lock; the lock drops before the ONE foreign `embed_query` call (ADR 0006 lock
   discipline); the scan opens sealed vectors in core only; hydration reuses the
   already-decrypted lexical corpus, so the hybrid path adds **no new plaintext exposure and
   no new at-rest artifact** — the fused page is as ephemeral as ADR 0005's index.

## Alternatives considered

- **Weighted score blending (normalize-then-sum).** Needs a calibration between scales that
  have none; every weight choice is a silent ranking policy that would drift per platform
  and per tuning pass. Rejected — and if a weighted scheme ever wins empirically, the
  weights become core constants behind the same API (the ticket pre-authorized this swap).
- **Consumer-side fusion (the ADR 0006 status quo).** Two implementations of an
  unfalsifiable-drift surface. Rejected for the reason in Context.
- **Adaptive/relative threshold (top-score-relative, per-query percentile).** Always passes
  *something*, so it structurally cannot say "nothing matched by meaning" — the padding the
  floor exists to prevent. A per-user calibration would additionally need labeled relevance
  data that does not exist on-device. Rejected (founder decision, 2026-07-29).
- **A vector-in API (`ranked_search(query, embedding, limit)`).** Would let hosts cache query
  embeddings, but adds the first vector-in FFI entry point and a second dims-validation seam
  for a ~0.8 s saving on a path that already costs a full corpus decrypt. Rejected; core
  calls the registered embedder, exactly like `semantic_search` (founder decision,
  2026-07-29). Easy to add later without disturbing this shape.

## Consequences

- Ranking policy is core-owned and version-pinned: a ranking change is a core release, seen
  by both platforms at their pin bump, never a platform-local tweak. ADR 0006's
  "consumer-side" consequence is superseded accordingly.
- **Reversibility is split.** The exported result shape (`RankedSearchPage` /
  `RankedHit` / `SemanticStatus`) is the same expensive-door class as ADR 0006's trait
  surface: reshaping or extending it after v0.14.0 is a breaking, coordinated iOS+Android
  change. The constants and fusion internals *behind* the shape (RRF's k, the floor, even
  swapping RRF for a weighted scheme) are the cheap half — a core release + pin bump with
  no host code change.
- The Rust fusion unit tests on fixed rankings ARE the cross-platform ranking contract
  (deterministic: total order with `ref_id`/kind tiebreaks). No parity oracle exists or can
  exist (GATING §5, as with ADR 0006); the fallback gate is those fixtures plus the
  Kotlin/Swift round-trip suites exercising the new surface with fake embedders.
- The floor constant is a quality knob with release-cadence latency. Accepted: better one
  honest constant tuned on device data than a host-configurable knob that forks ranking.
- **The floor is bound to the embedder descriptor, not to Braird.** It was measured against
  `embeddinggemma-300m-qat-seq256` at 256 dims; a model, quantization, or Matryoshka-width
  change re-keys the corpus (ADR 0006) and invalidates this number in the same breath. The
  calibration harness that produced it is `FloorCalibrationOnDeviceTest` on the Android side
  (the only place the real runtime exists) — re-run it on any descriptor change rather than
  carrying 0.35 forward on faith.
- Cost per call ≈ `search()` + one query embed + the full vector scan, all per-call and
  in-memory — the accepted ADR 0005/0006 posture at personal-archive scale; the ponytail
  caching path recorded in ADR 0005 remains the upgrade if profiling ever demands it.
