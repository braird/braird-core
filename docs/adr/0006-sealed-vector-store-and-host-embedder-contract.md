# ADR 0006 — Sealed vector store + host-embedder contract

- **Status:** Proposed (SUR-997; agent under the GCE gate — awaits `crypto-reviewer` + `sync-reviewer` + `naming-reviewer` + `architecture-decision-reviewer` + founder sign-off, per `GATING.md`).
- **Date:** 2026-07-24
- **Context tickets:** SUR-997 (this, the core leg of SUR-986), grounded in the SUR-529 spike verdict (GO: EmbeddingGemma-300M quantized @256-dim, host-runtime inference, re-embed per device, no ANN, no vector sync). Extends ADR 0003 (seal-at-write / ciphertext-at-rest) and ADR 0005 (decrypt-in-core read boundary). Consumed by SUR-998 (Android) / SUR-999 (iOS) via a pinned release; downstream features SUR-157 (semantic search), SUR-647/SUR-996 (selector similarity upgrades).

## Context

Semantic search needs a per-device embedding corpus over decrypted note text. The PWA's corpus
(`Xenova/all-MiniLM-L6-v2` q8 in Dexie, SUR-527) is a different model, a different vector space,
on a platform being sunset — nothing carries over, and it was never synced, so **no parity oracle
exists or can exist** for this surface (GATING §5 applies to the gate).

Two facts force real decisions. First, embedding **inference belongs to the hosts** (SUR-529:
LiteRT/Core ML own the NPU story; NNAPI is deprecated, `ort`/Candle have no Android NPU path), but
embedding **input is E2EE plaintext**, which only core may see — so the runtime and the plaintext
meet across an FFI boundary that must be shaped deliberately. Second, embeddings are too expensive
to rebuild per-search (~0.8 s per note on CPU), unlike the lexical index ADR 0005 rebuilds each
call — so vectors must **persist**, and a persisted derivative of plaintext needs the
ciphertext-at-rest treatment.

## The posture change this ADR names

**The `embeddings` table is the core's first persistent derived-from-plaintext artifact.**
Everything else at rest is either ciphertext (notes), plaintext-opaque metadata, or rebuilt
in-memory per use (the lexical index). Embedding vectors approximately invert to text, so they get
the full at-rest treatment: **sealed with the vault key (`Vault::seal_bytes`, the `0x02` byte
seal, AAD = note id), opened only in core where the Master Key lives, device-local by
construction** — the table is exempt from sync, snapshot export, and the outbox, and a test pins
that nothing embedding-related ever enqueues.

**Plaintext now also transits a host-supplied callback.** Previously decrypted text left core only
as display DTOs (ADR 0005). The `Embedder` trait hands one note's plaintext at a time to the
host's runtime and gets a vector back. The host must treat that text as displayed content: never
persist, log, or transmit it. Core's side of the discipline: no lock is ever held across the
callback, and at most one note's plaintext is in flight at a time.

## Options considered

| Decision | Chosen | Rejected alternative | Why rejected |
|---|---|---|---|
| **1. Where inference runs** | Host runtime behind a core-owned `#[uniffi::export(with_foreign)]` trait; core owns *what*/*when*, hosts own *how* | Embed inside the crate (`ort`/Candle) | No Android NPU path (NNAPI deprecated); official LiteRT builds exist for both hosts; a Rust runtime means owning the acceleration story on two platforms for no gain (SUR-529). |
| **2. Vector at-rest posture** | Sealed blobs (AAD = note id), f32 little-endian inside the seal, hard-deleted with their note | Plaintext vectors ("just floats") · int8 quantized (PWA parity) | Vectors invert to text — plaintext storage breaks the E2EE story. int8 existed for a Dexie footprint constraint that doesn't apply (256-dim f32 ≈ 5 MB at 5k notes) and stacks a second quantization under the model's own QAT. |
| **3. The (re)embed queue** | **Derived** — one metadata `LEFT JOIN` on `(corpus key, source token)`, where the token is `content_tag` (the stored HMAC of normalized plaintext) with an `u:{updated_at}` fallback | A staged queue written from enqueue/pull/reconcile/import (the ticket's literal item 5) | `content_tag` is free change-detection with **no decrypt**. A staged queue is mutable state plus four hook sites, each a place a missed hook silently stops the corpus updating; the derived query self-heals after any write path without that path knowing embeddings exist. Mirrors ADR 0005 decision 3 and the PWA's own (also derived) `noteIdsMissingEmbedding`. |
| **4. Corpus versioning** | Key = `model_id\|dims\|quantization\|f32le-v1` stored per row; key mismatch ⇒ hard-delete + re-queue (the PWA's `MODEL_CACHE_VERSION` pattern) | Migrate/re-project old vectors | Different models are different vector spaces; there is nothing to migrate. The trailing `f32le-v1` versions core's own storage format. |
| **5. Refusing a mismatched embedder** | Three structural checks: descriptor sanity at registration; returned-length vs declared dims on **every** embed; corpus-key change ⇒ invalidate | A model allowlist in core | An allowlist needs a core release per model change and fights host-owns-the-runtime. The prompt-template dimension is documented, not enforced (only the host can see its template; the contract is "template change ⇒ new `model_id`"). |
| **6. Scan** | Brute-force cosine top-k in core, per call | ANN index | SUR-529: scan stays interactive past ~100k docs, ~20× beyond a heavy archive. An index is persistent derived state with invalidation — cost without need. |

## Decisions (mechanics)

1. **Seal/open only in core.** The scan opens each candidate vector with the vault per call and
   discards the plaintext floats; raw vector bytes never rest anywhere. A blob that fails to open
   or decode is hard-deleted so the derived queue re-embeds its note — corruption self-heals and
   never wedges or surfaces.
2. **Vector lifetime = note lifetime.** The delete hook lives in `Store::apply_row` — the single
   choke point every note write funnels through (local stage, rebasing pull, import, pull sink) —
   so a `notes` tombstone from *any* path hard-deletes the vector in the same transaction when the
   caller holds one. An orphan sweep (once per embed pass) covers the crash window between the
   hook's two statements when no transaction was open.
3. **Skip markers make the queue honest.** Empty-text and undecryptable notes write a NULL-vector
   row at the current key + token (the decrypt-failure mirror of ADR 0005's index skip); without
   it the derived queue never drains. The note's next edit moves its token and re-queues it.
4. **Write-if-current.** The store lock is released across the host embed (~0.8 s); the write back
   re-checks the note's token under the lock and drops the vector if the text moved mid-embed (a
   stale vector written anyway would carry a current token and never re-queue).
5. **`EmbedError` is fieldless.** The error crosses foreign→Rust; a host-authored message must
   never transit into core's error strings (the `source_meta_json` rule, applied to the new
   direction). `Runtime` skips the item; `Unavailable` aborts the pass.
6. **Rebuild signalling is derived too.** `register_embedder` reports the *immediate* invalidation
   (`corpus_changed`/`invalidated`); the *durable* signal is `embed_pending_count()`, which
   survives a relaunch mid-rebuild (where a registration flag is correctly `false` while
   thousands are still pending). Hosts drive persistent "index rebuilding" UI off the count.

## Accepted residuals

- **Stale vectors stay searchable** between an edit and its re-embed — the note is findable on its
  old text. Recall over silence; the display text is always fetched fresh.
- **A model upgrade degrades search progressively** until the backfill completes (~27 min CPU at
  2k notes, SUR-529; minutes on NPU/seq256). Not a blackout: the scan filters on the current key,
  so re-embedded notes return immediately. Hosts blend lexical results meanwhile and notify per
  decision 6. The dual-corpus alternative (keep old vectors until the new corpus lands) buys out
  this window at the cost of doubled storage and two-key scan logic — declined.
- **arm64 foreign-trait marshalling is unproven until a device pass.** The Rust→foreign direction
  is the SUR-770/843 blind-spot class; every trait method takes one argument to stay clear of the
  spill window, and SUR-998's FTL lane is the acceptance test. A flaw found there ships as a patch
  release.

## Consequences

- The crypto boundary gains one carefully-shaped opening (the embed callback) and no new at-rest
  plaintext. `Store` stays ciphertext-and-sealed-blobs; `Vault` remains the only component that
  sees key material; `src/embeddings.rs` is pure math + contract types with no store or crypto
  dependency.
- Downstream consumers get two primitives: `semantic_search(query, limit)` (SUR-157) and
  `similar_notes(note_id, limit)` (SUR-647/SUR-996) — both returning `(note_id, cosine)` pairs;
  ranking policy, thresholds, and blending stay consumer-side.
- No parity gate exists for this surface (nothing to be parity *with*); the fallback gate is the
  Rust test suite plus hand-written Kotlin/Swift round-trip tests with a fake embedder — the only
  exercise of the Rust→foreign call direction until the SUR-998 device pass.
