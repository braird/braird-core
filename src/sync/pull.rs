//! Incremental pull (SUR-739 / SUR-652 core leg, extending SUR-725 / SUR-726). Mirrors surfc's
//! `fetchSince` + `mergeCloudRecords`: per synced table, fetch the rows the server has made visible
//! since a per-table cursor, merge **last-write-wins by `updated_at`** into the local store, apply
//! **tombstones** (incoming `deleted:1` is written but a soft-deleted row is never *resurrected*),
//! and advance the per-table cursor.
//!
//! Three invariants the gate (sync-reviewer + crypto-reviewer) turns on:
//!   - **Ciphertext stays at rest.** A pulled note's `text` is the enc:v2 ciphertext and is stored
//!     VERBATIM — never decrypted here (the inverse of push's seal-at-write). The host decrypts on
//!     demand via `Vault::decrypt_note`. Writing plaintext to SQLite would defeat E2EE.
//!   - **The cursor is the server `change_seq` watermark**, not a client clock. `change_seq` is
//!     stamped by surfc migration 0051 / trigger `t02_change_seq` when the server makes a row visible
//!     — distinct from the client-authored `updated_at` used for LWW. The cursor advances to the max
//!     `change_seq` seen, read from the **raw** incoming row BEFORE `apply_row` projects it away
//!     (`change_seq` is server-only, not a local descriptor column); the exclusive `change_seq >
//!     cursor` keyset re-fetches nothing already merged. This closes the SUR-739 **primary** hole: a
//!     delayed/offline flush's `change_seq` is allocated at flush time (high), so it's delivered on
//!     the next pull instead of skipped by a client-clock cursor. Absent cursor → 0 → full re-pull.
//!
//!     **Commit-ordered as of SUR-743.** `change_seq` is assigned in COMMIT order per user: surfc
//!     migration 0052 replaced 0051's per-table `nextval` (allocated at *statement* time) with a
//!     per-user lock-serialized counter, so a lower value can no longer commit AFTER the cursor
//!     passed a higher one (the old T1-allocates-100-stays-open / T2-allocates-101-commits skip).
//!     The exclusive keyset is therefore skip-safe by construction. The fix was **server-side and
//!     trigger-only** — the client already consumed a commit-ordered watermark correctly, so no
//!     change was needed here.
//!   - **Fetch is paginated** (SUR-652): one page of `PULL_PAGE_LIMIT` rows at a time, ordered by
//!     `change_seq` asc, advancing the cursor per page (a consistent prefix — a mid-pull failure
//!     resumes from the last merged page, never re-pulling merged rows or skipping unpulled ones),
//!     until a page shorter than the limit. Replaces the SUR-725 single unpaged GET, whose cursor
//!     advanced past everything beyond the server's `max_rows` cap (the SUR-652 skip-forever defect).
//!
//! Outbox rebase on an LWW win (SUR-736/738): when a pull applies a strictly-newer remote row for
//! a record that still has a queued local edit, that stale outbox entry is dropped in the SAME
//! transaction as the apply (via [`Store::apply_row_rebasing_outbox`]) — otherwise the next flush
//! would re-push the losing edit over the newer server row (a lost remote edit). Each record with a
//! dropped entry is reported as a [`SupersededEdit`] (the local edit lost LWW and was dropped;
//! full server-side conflict detection is out of scope — SUR-738 ratifies the client-side signal).
//!
//! Source of truth: surfc `src/supabase.js` (`fetchSince` / `SYNC_PAGE_SIZE`), `src/db.js`
//! (`mergeCloudRecords`), `src/hooks/useAuth.js` (per-table `lastSeq:<table>` cursor).

use serde_json::Value;

use super::http::PostgrestSink;
use super::SupersededEdit;
use crate::store::{table_schema, Store};

/// PostgREST page size for the incremental pull (SUR-652) — matches the PWA's `SYNC_PAGE_SIZE`
/// (`surfc/src/supabase.js`). `pull_table` loops `fetch_page` until a page shorter than this.
const PULL_PAGE_LIMIT: i64 = 1000;

/// One failed table with its (clipped) underlying error. SUR-1031: this used to be a bare table
/// name — the `Err(_)` below cost three field-debugging sessions on one bug family, because an
/// HTTP 429, a 401, and a merge failure were indistinguishable in what the host saw. The error text
/// is host-visible (Android logs it in debug builds only, per its SUR-764 posture); [`clip_error`]
/// bounds it, and merge errors never quote row content (serde errors are positional).
#[derive(Debug)]
pub struct TableFailure {
    pub table: String,
    pub error: String,
}

impl std::fmt::Display for TableFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.table, self.error)
    }
}

/// Render failures for an aggregated error/log line: `books (PostgREST 429 — …), notes (…)`.
pub fn describe_failures(failures: &[TableFailure]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Bound a failure string before it rides an aggregated host-facing error — a proxy error page can
/// be a whole HTML document. Char-based, so it can't split a UTF-8 sequence.
fn clip_error(e: String) -> String {
    const MAX_CHARS: usize = 200;
    if e.chars().count() <= MAX_CHARS {
        e
    } else {
        let mut clipped: String = e.chars().take(MAX_CHARS).collect();
        clipped.push('…');
        clipped
    }
}

/// Counts across a whole pull (one or more tables). `failed_tables` are the tables whose fetch or
/// merge errored — their cursor is left at the last merged page so the window re-pulls next time
/// (per-table failure isolation, the SUR-659 per-table-cursor rationale).
#[derive(Debug, Default)]
pub struct PullResult {
    pub pulled: usize,
    pub merged: usize,
    pub skipped_tombstones: usize,
    /// Local edits dropped because a strictly-newer remote row won LWW (SUR-736/738).
    pub superseded: Vec<SupersededEdit>,
    pub failed_tables: Vec<TableFailure>,
}

#[derive(Debug, Default)]
struct TableStats {
    pulled: usize,
    merged: usize,
    skipped_tombstones: usize,
    superseded: Vec<SupersededEdit>,
}

/// Pull `tables` incrementally, paginating each by the server `change_seq` watermark. A table that
/// fails is isolated: its cursor stays at the last merged page and other tables proceed.
pub async fn pull<S: PostgrestSink>(
    store: &Store,
    sink: &S,
    tables: &[&str],
) -> Result<PullResult, String> {
    let mut result = PullResult::default();
    for &table in tables {
        match pull_table(store, sink, table, PULL_PAGE_LIMIT).await {
            Ok(stats) => {
                result.pulled += stats.pulled;
                result.merged += stats.merged;
                result.skipped_tombstones += stats.skipped_tombstones;
                result.superseded.extend(stats.superseded);
            }
            Err(e) => {
                // SUR-1031: carry the error, don't just name the table — a silent failure would
                // read as "nothing to pull", and a nameless one is undiagnosable from the host
                // (the 2026-08-03 books incident). The cursor stays at the last merged page
                // (retry next pull); the caller decides if all-tables-failed is a hard error.
                let failure = TableFailure {
                    table: table.to_string(),
                    error: clip_error(e),
                };
                eprintln!("pull: table {failure} failed (cursor at last merged page)");
                result.failed_tables.push(failure);
            }
        }
    }
    Ok(result)
}

/// Pull one table, paging by `change_seq` in batches of `page_size`. The cursor advances to the max
/// `change_seq` of each merged page before the next fetch, so a page-fetch failure mid-pagination
/// leaves the cursor at the last fully-merged page (the failed + remaining pages re-pull next time).
async fn pull_table<S: PostgrestSink>(
    store: &Store,
    sink: &S,
    table: &str,
    page_size: i64,
) -> Result<TableStats, String> {
    let pk = table_schema(table)
        .ok_or_else(|| format!("unknown synced table: {table}"))?
        .pk[0];
    let mut cursor = store
        .get_seq_cursor(table)
        .map_err(|e| format!("read cursor {table}: {e}"))?
        .unwrap_or(0);

    let mut stats = TableStats::default();
    loop {
        // SUR-1031 root-cause arm: the FIRST request of a pull volley can eat a connection that died
        // idle — in the 2026-08-03 field incident, `books` (first in `synced_schema()`) failed 12/12
        // while the other seven tables' requests all 200'd, and the gateway logs showed the failing
        // requests never arrived at Supabase at all (client-side, a pooled/h2 connection-reuse race).
        // A page fetch is an idempotent GET, so ONE immediate re-attempt — riding the fresh connection
        // the failure just forced open — is safe and collapses the class. A persistent failure still
        // fails (with both attempts' errors carried), keeping the per-table isolation semantics.
        let rows = match sink.fetch_page(table, cursor, page_size).await {
            Ok(rows) => rows,
            // Retry is a WHITELIST (Codex review): only errors the production sink explicitly
            // classified as transport-level (`transport: ` — the dead-reused-connection class the
            // gateway logs proved) get the one immediate re-attempt. Everything else fails without
            // a second request: an application-level PostgREST response was already answered (a 429
            // re-GET worsens the throttling it reports), and the import sanitizer's validation
            // failures must fail CLOSED — a malformed preflight page never deserves a second chance
            // its contract forbids. String-prefix classification because the sink trait is
            // String-typed end to end; a typed error enum sweeps every sink impl — founder's call.
            Err(first) if !first.starts_with("transport: ") => return Err(first),
            Err(first) => {
                let first = clip_error(first);
                eprintln!("pull: {table} page fetch failed ({first}); retrying once on a fresh connection");
                sink.fetch_page(table, cursor, page_size)
                    .await
                    .map_err(|second| {
                        format!("{second} (persisted after retry; first attempt: {first})")
                    })?
            }
        };
        let page_len = rows.len();
        let mut page_max = cursor;

        for row in &rows {
            let Some(obj) = row.as_object() else { continue };
            let Some(id) = obj.get(pk).and_then(|v| v.as_str()) else {
                continue; // a row without its pk can't be merged — skip defensively
            };
            stats.pulled += 1;

            // Track the page's max `change_seq` from the RAW row — read it here, before the merge,
            // because `apply_row` projects `change_seq` (a server-only, non-descriptor column) away.
            // EVERY processed row advances the watermark (merged, tombstone-skipped, or LWW-loser
            // alike), so a page of nothing-but-skips still makes forward progress. The server stamps
            // it NOT NULL (migration 0051); a missing value would leave the page non-advancing (see
            // the loop-exit guard below).
            //
            // THIS IS WHY A ROW CANNOT SIMPLY BE SKIPPED ON ARRIVAL (SUR-1070). Advancing here, before
            // any merge decision, means a row this loop `continue`s past is never re-delivered — the
            // device diverges permanently, silently, with no retry. Note the asymmetry: an ERROR
            // return is different, because `?` exits before the `set_seq_cursor` below, so the cursor
            // is not persisted and the row returns next pull — at the cost of failing that table on
            // every pull, which `pull_then_flush` turns into a flush abort for EVERY table. Neither
            // shape is a usable guard; validating pulled content needs a quarantine + retry rule. See
            // the decision recorded on `Store::apply_row`.
            if let Some(seq) = obj.get("change_seq").and_then(Value::as_i64) {
                page_max = page_max.max(seq);
            }

            let incoming_updated = obj.get("updated_at").and_then(Value::as_i64).unwrap_or(0);
            let incoming_deleted = obj.get("deleted").and_then(Value::as_bool).unwrap_or(false);

            // The local row's updated_at (None = no local row) is the only thing the LWW decision
            // needs; a full-row replace on a win comes from `apply_row`.
            let local_updated = store
                .get_row(table, id)
                // No record id in the error (Codex review): SUR-1031 carries these strings across
                // the FFI, and SyncError's contract is coarse — never per-record server detail.
                .map_err(|e| format!("read local {table} row: {e}"))?
                .map(|r| r.get("updated_at").and_then(Value::as_i64).unwrap_or(0));

            // Tombstone: a delete for a row we don't have locally is NOT resurrected — mirrors JS
            // `if (n.deleted && !local) continue`. (A delete for a row we DO have flows through LWW
            // below and writes the tombstone if it's newer.)
            if incoming_deleted && local_updated.is_none() {
                stats.skipped_tombstones += 1;
                continue;
            }

            // Last-write-wins by `updated_at`, STRICT `>` so a tie keeps the local row — mirrors JS
            // `if (!local || cloud.updated_at > local.updatedAt)`. (Distinct from the cursor's
            // change_seq keyset: LWW is on the client `updated_at`, delivery is on the server
            // `change_seq` — the two axes SUR-739 separates.)
            //
            // WHOLE-ROW LWW, including array/composite columns (SUR-737, ratified): the winner's
            // `tags` / `source_meta` / `leaf_ids` replace the local ones wholesale — there is NO
            // element-level union (a union can't express a delete). This is table-agnostic, so it
            // holds for every SUR-726 fan-out table; the convergence contract + rationale live on
            // `store::synced_schema`, and any change here is wire-visible (must move in lockstep with
            // the PWA's `mergeCloudRecords`). Ratification pin tests: `sur737_*` below.
            let should_apply = match local_updated {
                None => true,
                Some(local_ts) => incoming_updated > local_ts,
            };
            if should_apply {
                // Apply the winner AND drop any now-stale queued edit for this record atomically
                // (SUR-736) — leaving it would let the next flush re-push it over this newer row.
                let dropped = store
                    .apply_row_rebasing_outbox(table, obj, incoming_updated)
                    // Coarse like the read error above — table + error class, no record id.
                    .map_err(|e| format!("apply a {table} row: {e}"))?;
                stats.merged += 1;
                // A dropped entry = a local edit superseded by the remote winner (SUR-738). Key it
                // by the newest discarded stamp.
                if let Some(discarded) = dropped.iter().map(|(_, ts)| *ts).max() {
                    stats.superseded.push(SupersededEdit {
                        table: table.to_string(),
                        record_id: id.to_string(),
                        discarded_updated_at: discarded,
                        winning_updated_at: incoming_updated,
                    });
                }
            }
        }

        // Advance the cursor for this page after its merge (a consistent prefix). An empty page
        // leaves the cursor untouched — with a keyset watermark that's a cheap indexed no-op, not
        // the full `since=0` rescan the old epoch-ms cursor would have re-run each pull.
        let advanced = page_max > cursor;
        if advanced {
            store
                .set_seq_cursor(table, page_max)
                .map_err(|e| format!("advance cursor {table}: {e}"))?;
            cursor = page_max;
        }

        if page_len < page_size as usize {
            break; // short (or empty) page → the last page
        }
        if !advanced {
            // Liveness backstop for the `loop`: a FULL page that didn't advance the watermark AT ALL
            // (every row's `change_seq` unparseable) can't make progress and would spin forever, so
            // fail the table loudly instead. This is defensive only — migration 0051 stamps
            // `change_seq` NOT NULL, so no synced row is ever missing it; that NOT NULL is what
            // guarantees completeness, this guard only guarantees termination. (A *partially* seq-less
            // full page — impossible under 0051 — would still advance past the seq-less rows; we don't
            // add a per-row parse-fail check for a can't-happen case.)
            return Err(format!(
                "pull {table}: a full page did not advance the change_seq cursor — every row is \
                 missing change_seq (server must stamp it NOT NULL, migration 0051)"
            ));
        }
    }

    // The pagination loop reached its last page — the `break` above is its only normal exit, so
    // arriving here means every page this table had was fetched and merged. Record the receipt
    // (SUR-1075).
    //
    // Deliberately NOT inferable from the cursor: an empty page advances no cursor (see the comment
    // above the advance), so a successful pull of an empty table writes none. A consumer that reads
    // meaning into an empty table would then treat a silently-failed pull as authoritative, because
    // `SyncEngine::pull` returns `Ok` on a partial failure and names no table.
    //
    // Written HERE rather than in `pull`'s `Ok(stats)` arm so no caller can mint a receipt for a
    // table whose pagination it never drove to the end.
    store
        .mark_pull_complete(table)
        .map_err(|e| format!("record pull receipt {table}: {e}"))?;

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::sync::SupersededEdit;
    use serde_json::json;
    use std::collections::HashMap;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Stub PostgREST seam for the merge/LWW/tombstone/rebase tests: returns canned rows per table.
    /// It does NOT keyset on `after_seq` (the canned pages are always shorter than the limit → one
    /// fetch); real pagination is exercised by [`PagingSink`]. `failing(table)` errors that table's
    /// fetch. Pull never upserts, so `upsert` is inert.
    struct MapSink {
        rows: HashMap<String, Vec<Value>>,
        fail: Option<String>,
        /// How many more fetches of [`fail`]'s table error: `u32::MAX` = persistent ([`failing`]),
        /// `1` = the SUR-1031 transient dead-connection shape ([`failing_once`]).
        fail_remaining: std::cell::Cell<u32>,
        /// Error with the application-level `PostgREST …` shape instead of a transport string.
        fail_postgrest: bool,
    }
    impl MapSink {
        fn new() -> Self {
            Self {
                rows: HashMap::new(),
                fail: None,
                fail_remaining: std::cell::Cell::new(0),
                fail_postgrest: false,
            }
        }
        fn with(mut self, table: &str, rows: Vec<Value>) -> Self {
            // Stamp a per-table monotonic `change_seq` (1-based, insertion order) onto each row that
            // lacks one — mirrors the server's `t02_change_seq` trigger, which stamps it NOT NULL on
            // every synced row (SUR-739). The pull cursor advances to the max of these.
            let stamped = rows
                .into_iter()
                .enumerate()
                .map(|(i, mut r)| {
                    if r.get("change_seq").is_none() {
                        r["change_seq"] = json!(i as i64 + 1);
                    }
                    r
                })
                .collect();
            self.rows.insert(table.to_string(), stamped);
            self
        }
        fn failing(mut self, table: &str) -> Self {
            self.fail = Some(table.to_string());
            self.fail_remaining.set(u32::MAX);
            self
        }
        /// The SUR-1031 transient shape: the named table's FIRST fetch errors (a dead pooled
        /// connection), every later one succeeds — the retry must absorb it.
        fn failing_once(mut self, table: &str) -> Self {
            self.fail = Some(table.to_string());
            self.fail_remaining.set(1);
            self
        }
        /// An application-level PostgREST response — the shape the retry must NOT touch.
        fn failing_postgrest(mut self, table: &str) -> Self {
            self.fail = Some(table.to_string());
            self.fail_remaining.set(u32::MAX);
            self.fail_postgrest = true;
            self
        }
    }
    impl PostgrestSink for MapSink {
        async fn upsert(&self, _t: &str, _c: &str, _r: &Value) -> Result<(), String> {
            Ok(())
        }
        async fn fetch_page(
            &self,
            table: &str,
            _after_seq: i64,
            limit: i64,
        ) -> Result<Vec<Value>, String> {
            if self.fail.as_deref() == Some(table) && self.fail_remaining.get() > 0 {
                // Persistent (u32::MAX) keeps failing; the transient shape (1) is consumed here, so
                // the SUR-1031 retry's second attempt gets a live connection.
                if self.fail_remaining.get() != u32::MAX {
                    self.fail_remaining.set(self.fail_remaining.get() - 1);
                }
                if self.fail_postgrest {
                    return Err("PostgREST 429".to_string()); // the real sink is status-only (redacted)
                }
                return Err(format!("transport: {table} fetch failed"));
            }
            let mut rows = self.rows.get(table).cloned().unwrap_or_default();
            rows.truncate(limit as usize);
            Ok(rows)
        }
    }

    /// A keyset-faithful stub: holds one table's rows (each with an explicit `change_seq`) and serves
    /// real `change_seq > after_seq` pages ordered asc, capped at `limit` — so the pagination LOOP in
    /// `pull_table` is exercised. `failing_after(n)` makes every fetch from the (0-based) n-th on
    /// error — persistent, so the SUR-1031 single retry can't absorb it — to prove a mid-pagination
    /// failure leaves the cursor at the last fully-merged page.
    struct PagingSink {
        rows: Vec<Value>,
        calls: std::cell::Cell<u32>,
        fail_after: Option<u32>,
    }
    impl PagingSink {
        fn new(rows: Vec<Value>) -> Self {
            Self {
                rows,
                calls: std::cell::Cell::new(0),
                fail_after: None,
            }
        }
        fn failing_after(mut self, n: u32) -> Self {
            self.fail_after = Some(n);
            self
        }
    }
    impl PostgrestSink for PagingSink {
        async fn upsert(&self, _t: &str, _c: &str, _r: &Value) -> Result<(), String> {
            Ok(())
        }
        async fn fetch_page(
            &self,
            _table: &str,
            after_seq: i64,
            limit: i64,
        ) -> Result<Vec<Value>, String> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            if self.fail_after == Some(n) {
                // Unclassified (no `transport: ` prefix), so the SUR-1031 retry whitelist never
                // absorbs it — the mid-pagination cursor-isolation pin stays intact.
                return Err("simulated mid-pagination fetch failure".into());
            }
            let mut page: Vec<Value> = self
                .rows
                .iter()
                // A row WITH change_seq keysets normally; a row WITHOUT one flows through unfiltered
                // (only the contract-violation test seeds those — it needs a full non-advancing page).
                .filter(|r| match r["change_seq"].as_i64() {
                    Some(seq) => seq > after_seq,
                    None => true,
                })
                .cloned()
                .collect();
            page.sort_by_key(|r| r["change_seq"].as_i64().unwrap_or(0));
            page.truncate(limit as usize);
            Ok(page)
        }
    }

    fn note(id: &str, updated_at: i64, deleted: bool, text: &str) -> Value {
        json!({ "id": id, "text": text, "content_tag": "tag", "updated_at": updated_at, "deleted": deleted })
    }

    fn apply_local(store: &Store, table: &str, row: Value) {
        store.apply_row(table, row.as_object().unwrap()).unwrap();
    }

    /// Queue a pending outbox entry for `notes/id` stamped `ts` (the offline-first shape: a local
    /// write leaves both a synced row and an outbox row). Returns the outbox id.
    fn enqueue_pending(store: &Store, id: &str, ts: i64) -> i64 {
        store
            .enqueue(
                "notes",
                id,
                &json!({ "id": id, "updated_at": ts }).to_string(),
                ts,
            )
            .unwrap()
    }

    #[test]
    fn merges_new_rows_and_advances_each_cursor() {
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new()
            .with(
                "books",
                vec![json!({ "id": "b1", "title": "T", "updated_at": 1000, "deleted": false })],
            )
            .with("notes", vec![note("n1", 1000, false, "enc:v2:x")]);

        let res = block(pull(&store, &sink, &["books", "notes"])).unwrap();

        assert_eq!(res.pulled, 2);
        assert_eq!(res.merged, 2);
        assert!(store.get_row("books", "b1").unwrap().is_some());
        assert!(store.get_row("notes", "n1").unwrap().is_some());
        // Cursor = the max change_seq merged (one row per table → change_seq 1).
        assert_eq!(store.get_seq_cursor("books").unwrap(), Some(1));
        assert_eq!(store.get_seq_cursor("notes").unwrap(), Some(1));
    }

    #[test]
    fn ciphertext_is_stored_verbatim_not_decrypted() {
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with("notes", vec![note("n1", 1000, false, "enc:v2:abcDEF")]);
        block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("enc:v2:abcDEF"),
            "pull must store the ciphertext verbatim (no decrypt at rest)"
        );
    }

    #[test]
    fn lww_keeps_local_when_incoming_is_older() {
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 2000, false, "local"));
        let sink = MapSink::new().with("notes", vec![note("n1", 1000, false, "remote-old")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.merged, 0);
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("local")
        );
    }

    #[test]
    fn lww_overwrites_when_incoming_is_newer() {
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "local"));
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote-new")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.merged, 1);
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("remote-new")
        );
    }

    #[test]
    fn lww_tie_keeps_local() {
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "local"));
        let sink = MapSink::new().with("notes", vec![note("n1", 1000, false, "remote-tie")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.merged, 0, "a tie keeps local (strict >)");
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("local")
        );
    }

    #[test]
    fn tombstone_is_not_resurrected_when_no_local_row() {
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, true, "")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.skipped_tombstones, 1);
        assert_eq!(res.merged, 0);
        assert!(
            store.get_row("notes", "n1").unwrap().is_none(),
            "a delete for a row we never had must not be inserted"
        );
        // A skipped tombstone still advances the cursor — we've seen it, no need to re-pull it.
        assert_eq!(store.get_seq_cursor("notes").unwrap(), Some(1));
    }

    #[test]
    fn tombstone_is_applied_over_an_older_local_row() {
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "live"));
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, true, "")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.merged, 1);
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["deleted"],
            json!(true),
            "a newer delete flips the local row to a tombstone"
        );
    }

    #[test]
    fn stale_tombstone_does_not_revive_a_newer_local_row() {
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 3000, false, "fresh-local-edit"));
        // A delete older than the local edit must lose LWW — the local edit stays live.
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, true, "")]);
        let res = block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(res.merged, 0);
        let row = store.get_row("notes", "n1").unwrap().unwrap();
        assert_eq!(row["deleted"], json!(false));
        assert_eq!(row["text"], json!("fresh-local-edit"));
    }

    #[test]
    fn per_table_failure_isolates_the_cursor() {
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new()
            .with(
                "books",
                vec![json!({ "id": "b1", "title": "T", "updated_at": 1000, "deleted": false })],
            )
            .failing("notes");
        let res = block(pull(&store, &sink, &["books", "notes"])).unwrap();

        assert_eq!(res.merged, 1, "books still merged");
        // SUR-1031: the failure carries its underlying error, not just the table name — an Err(_)
        // here once made an HTTP 429 and a decode failure indistinguishable from the host.
        let failures: Vec<(&str, &str)> = res
            .failed_tables
            .iter()
            .map(|f| (f.table.as_str(), f.error.as_str()))
            .collect();
        assert_eq!(
            failures,
            vec![(
                "notes",
                "transport: notes fetch failed (persisted after retry; first attempt: transport: notes fetch failed)"
            )],
        );
        assert_eq!(store.get_seq_cursor("books").unwrap(), Some(1));
        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            None,
            "failed table's cursor stays put so its window re-pulls"
        );
    }

    #[test]
    fn an_application_level_response_is_never_retried() {
        // A server that ANSWERED (PostgREST 4xx/5xx) must not be asked the identical question again
        // — a 429 answered with a duplicate GET worsens the throttling it reports. The error's
        // missing "persisted after retry" suffix is the proof no second attempt was made.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().failing_postgrest("books");
        let res = block(pull(&store, &sink, &["books"])).unwrap();

        let failures: Vec<(&str, &str)> = res
            .failed_tables
            .iter()
            .map(|f| (f.table.as_str(), f.error.as_str()))
            .collect();
        assert_eq!(failures, vec![("books", "PostgREST 429")]);
    }

    #[test]
    fn transient_first_fetch_failure_is_absorbed_by_the_retry() {
        // SUR-1031 root-cause arm: the volley's first request eating a dead pooled connection must
        // not fail the table — the immediate re-attempt rides the fresh connection the failure
        // forced open, and the pull completes as if nothing happened.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new()
            .with(
                "books",
                vec![json!({ "id": "b1", "title": "T", "updated_at": 1000, "deleted": false })],
            )
            .failing_once("books");
        let res = block(pull(&store, &sink, &["books"])).unwrap();

        assert!(
            res.failed_tables.is_empty(),
            "the retry absorbed the dead connection"
        );
        assert_eq!(res.merged, 1);
        assert_eq!(store.get_seq_cursor("books").unwrap(), Some(1));
    }

    #[test]
    fn clip_error_bounds_a_proxy_page_but_keeps_short_errors_whole() {
        // SUR-1031: a Cloudflare/proxy failure body can be a whole HTML document — the clip keeps
        // the aggregated host-facing error bounded without touching ordinary errors.
        assert_eq!(
            clip_error("PostgREST 429 — rate limited".into()),
            "PostgREST 429 — rate limited"
        );
        let long = "x".repeat(500);
        let clipped = clip_error(long);
        assert_eq!(clipped.chars().count(), 201, "200 chars + ellipsis");
        assert!(clipped.ends_with('…'));
    }

    #[test]
    fn empty_pull_leaves_cursor_unadvanced() {
        // With a keyset-by-change_seq cursor, an empty pull is a cheap indexed no-op — there is
        // nothing to advance to (unlike the retired epoch-ms cursor, which advanced to `now` to
        // avoid re-scanning from 0). Re-pulling `change_seq > 0` stays cheap.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with("notes", vec![]);
        block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(store.get_seq_cursor("notes").unwrap(), None);
    }

    // ── SUR-1075 pull receipts (a receipt is not a watermark) ─────────────────

    #[test]
    fn a_successful_empty_pull_records_a_receipt_without_a_cursor() {
        // THE case the receipt exists for. An empty page advances no cursor, so cursor-absence
        // cannot tell "never pulled" from "pulled, nothing there" — and on a new account the
        // second is the normal flow. The receipt separates them; gating on the cursor instead
        // would suppress every first-run experience forever.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with("notes", vec![]);

        block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            None,
            "an empty page still advances nothing"
        );
        assert!(
            store.has_completed_pull("notes").unwrap(),
            "but the pull DID complete, and that is the fact consumers need"
        );
    }

    #[test]
    fn a_failed_table_records_no_receipt_while_its_sibling_does() {
        // Per-table isolation extends to the receipt: `pull` returns Ok on a partial failure, so
        // the receipt is the only per-table outcome a later reader can see.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new()
            .with(
                "books",
                vec![json!({ "id": "b1", "title": "T", "updated_at": 1000, "deleted": false })],
            )
            .failing("notes");

        let res = block(pull(&store, &sink, &["books", "notes"])).unwrap();

        assert_eq!(res.failed_tables.len(), 1, "a PARTIAL failure, still Ok");
        assert!(store.has_completed_pull("books").unwrap());
        assert!(
            !store.has_completed_pull("notes").unwrap(),
            "the failed table must not look pulled"
        );
    }

    #[test]
    fn a_mid_pagination_failure_records_no_receipt_despite_a_merged_page() {
        // Partial progress is not completion. The first page merges and advances the cursor; the
        // second fetch fails. A receipt here would claim the table is fully known when its tail
        // never arrived.
        let store = Store::open_in_memory().unwrap();
        let rows: Vec<Value> = (1..=4)
            .map(|i| {
                json!({ "id": format!("n{i}"), "text": format!("enc:v2:{i}"), "content_tag": "t",
                        "updated_at": 1000 + i, "deleted": false, "change_seq": i })
            })
            .collect();
        let sink = PagingSink::new(rows).failing_after(1);

        assert!(block(pull_table(&store, &sink, "notes", 2)).is_err());

        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            Some(2),
            "the first page really did merge"
        );
        assert!(
            !store.has_completed_pull("notes").unwrap(),
            "a partly-pulled table is not a pulled table"
        );
    }

    #[test]
    fn a_receipt_latches_through_a_later_failure() {
        // Once a table has completed a pull, its rows are a valid LWW merge base. A later failure
        // makes it STALE — what every consumer already tolerates — not unknown. Clearing the
        // receipt would flip a working device back to "cannot tell" on one flaky request.
        let store = Store::open_in_memory().unwrap();
        block(pull(
            &store,
            &MapSink::new().with("notes", vec![]),
            &["notes"],
        ))
        .unwrap();
        assert!(store.has_completed_pull("notes").unwrap());

        block(pull(&store, &MapSink::new().failing("notes"), &["notes"])).unwrap();

        assert!(
            store.has_completed_pull("notes").unwrap(),
            "a failure after a completed pull means stale, not unknown"
        );
    }

    #[test]
    fn the_absorbed_transient_retry_still_records_a_receipt() {
        // The SUR-1031 one-shot retry makes the table succeed, so it must also make it complete —
        // the receipt tracks the outcome, not whether the first request happened to land.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with("notes", vec![]).failing_once("notes");

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert!(res.failed_tables.is_empty());
        assert!(store.has_completed_pull("notes").unwrap());
    }

    // ── SUR-652 keyset pagination (the pull loops fetch_page until a short page) ───

    #[test]
    fn paged_pull_crosses_page_boundaries() {
        // Five rows, page size 2 → pages [1,2] [3,4] [5]: three fetches, every row merged, cursor at
        // the last change_seq. Exercises the pagination loop a single unpaged GET would miss.
        let store = Store::open_in_memory().unwrap();
        let rows: Vec<Value> = (1..=5)
            .map(|i| {
                json!({ "id": format!("n{i}"), "text": format!("enc:v2:{i}"), "content_tag": "t",
                        "updated_at": 1000 + i, "deleted": false, "change_seq": i })
            })
            .collect();
        let sink = PagingSink::new(rows);

        let stats = block(pull_table(&store, &sink, "notes", 2)).unwrap();

        assert_eq!(stats.merged, 5, "every row across all pages merged");
        assert_eq!(stats.pulled, 5);
        assert_eq!(sink.calls.get(), 3, "two full pages + one short page");
        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            Some(5),
            "cursor at the last change_seq seen"
        );
        for i in 1..=5 {
            assert!(store.get_row("notes", &format!("n{i}")).unwrap().is_some());
        }
    }

    #[test]
    fn cursor_advances_only_through_the_last_merged_page_on_mid_pull_failure() {
        // Page 1 [1,2] merges and advances the cursor to 2; the page-2 fetch then fails. The cursor
        // must sit at 2 (the last fully-merged page) — the failed + remaining pages re-pull next
        // time, with no partial page committed past the failure and no re-pull of pages 1's rows.
        let store = Store::open_in_memory().unwrap();
        let rows: Vec<Value> = (1..=4)
            .map(|i| {
                json!({ "id": format!("n{i}"), "text": "enc:v2:x", "content_tag": "t",
                        "updated_at": 1000 + i, "deleted": false, "change_seq": i })
            })
            .collect();
        let sink = PagingSink::new(rows).failing_after(1); // 0-based: 2nd fetch errors

        let outcome = block(pull_table(&store, &sink, "notes", 2));

        assert!(
            outcome.is_err(),
            "the mid-pagination fetch failure surfaces"
        );
        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            Some(2),
            "cursor sits at the last fully-merged page"
        );
        assert!(store.get_row("notes", "n1").unwrap().is_some());
        assert!(store.get_row("notes", "n2").unwrap().is_some());
        assert!(
            store.get_row("notes", "n3").unwrap().is_none(),
            "page 2 never merged"
        );
    }

    #[test]
    fn a_full_page_missing_change_seq_errors_rather_than_looping() {
        // Contract guard: a FULL page whose rows carry no change_seq can't advance the watermark and
        // would loop forever. The server stamps change_seq NOT NULL (0051), so this only fires on a
        // broken server — we fail the table loudly instead of spinning.
        let store = Store::open_in_memory().unwrap();
        // Two rows, NO change_seq, page size 2 → a full page that can't advance.
        let rows = vec![
            json!({ "id": "n1", "text": "enc:v2:x", "content_tag": "t", "updated_at": 1, "deleted": false }),
            json!({ "id": "n2", "text": "enc:v2:y", "content_tag": "t", "updated_at": 2, "deleted": false }),
        ];
        let sink = PagingSink::new(rows);
        let outcome = block(pull_table(&store, &sink, "notes", 2));
        assert!(
            outcome.is_err(),
            "a full non-advancing page must error, not loop forever"
        );
        assert_eq!(store.get_seq_cursor("notes").unwrap(), None);
    }

    #[test]
    fn a_stale_legacy_ms_cursor_does_not_gate_the_pull_and_is_retired() {
        // A device upgrading from the pre-SUR-739 epoch-ms cursor: the legacy `sync:cursor:notes` key
        // must NOT be read as a change_seq (a ~1.7e12 value would filter out every row). The new
        // cursor (`sync:seq:notes`) is absent → 0 → a full re-pull; the legacy key is then retired.
        let store = Store::open_in_memory().unwrap();
        store
            .meta_set("sync:cursor:notes", "1700000000000")
            .unwrap(); // legacy epoch-ms key
        let sink = MapSink::new().with("notes", vec![note("n1", 1000, false, "enc:v2:x")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(
            res.merged, 1,
            "the legacy ms key did not gate the pull (full re-pull from 0)"
        );
        assert_eq!(
            store.get_seq_cursor("notes").unwrap(),
            Some(1),
            "the new change_seq cursor is set"
        );
        assert_eq!(
            store.meta_get("sync:cursor:notes").unwrap(),
            None,
            "the legacy epoch-ms cursor key is retired on the first change_seq pull"
        );
    }

    // ── SUR-736/738 outbox rebase on an LWW win + conflict signal ─────────────

    #[test]
    fn rebase_drops_stale_pending_edit_and_surfaces_conflict() {
        // (1) pending T1, incoming T2 > T1 → row = remote, outbox drained, one conflict surfaced.
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "local"));
        enqueue_pending(&store, "n1", 1000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 1);
        assert_eq!(
            res.superseded,
            vec![SupersededEdit {
                table: "notes".into(),
                record_id: "n1".into(),
                discarded_updated_at: 1000,
                winning_updated_at: 2000,
            }]
        );
        assert!(
            store.outbox_items().unwrap().is_empty(),
            "the stale queued edit is rebased away — the next flush can't re-push it (SUR-736)"
        );
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("remote")
        );
    }

    #[test]
    fn newer_local_edit_blocks_rebase_and_keeps_pending() {
        // (2) pending T3, incoming T2 < T3 → no apply, outbox intact, no conflict.
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 3000, false, "local-newer"));
        enqueue_pending(&store, "n1", 3000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote-older")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 0);
        assert!(res.superseded.is_empty());
        assert_eq!(
            store.outbox_items().unwrap().len(),
            1,
            "pending edit survives"
        );
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("local-newer")
        );
    }

    #[test]
    fn tie_keeps_local_and_does_not_rebase() {
        // (3) incoming == local row ts → keep local, outbox intact (rebase never runs).
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 2000, false, "local"));
        enqueue_pending(&store, "n1", 2000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote-tie")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 0);
        assert!(res.superseded.is_empty());
        assert_eq!(store.outbox_items().unwrap().len(), 1);
    }

    #[test]
    fn incoming_tombstone_rebases_a_pending_edit() {
        // (4) incoming tombstone T2 over pending edit T1 → tombstone applied, entry dropped.
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "local-live"));
        enqueue_pending(&store, "n1", 1000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, true, "")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 1);
        assert_eq!(res.superseded.len(), 1);
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["deleted"],
            json!(true)
        );
        assert!(
            store.outbox_items().unwrap().is_empty(),
            "the pending edit is dropped by the newer delete"
        );
    }

    #[test]
    fn incoming_live_edit_rebases_a_pending_delete() {
        // (5) pending delete T1 vs incoming live edit T2 → live row applied, delete dropped.
        // Symmetric with `stale_tombstone_does_not_revive_a_newer_local_row` — a newer edit beats
        // an older delete; this is LWW, not a resurrection violation (resurrection is a delete for a
        // row this device never had, guarded separately).
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, true, ""));
        enqueue_pending(&store, "n1", 1000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote-live")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 1);
        assert_eq!(res.superseded.len(), 1);
        let row = store.get_row("notes", "n1").unwrap().unwrap();
        assert_eq!(
            row["deleted"],
            json!(false),
            "newer live edit beats older delete"
        );
        assert_eq!(row["text"], json!("remote-live"));
        assert!(
            store.outbox_items().unwrap().is_empty(),
            "pending delete dropped"
        );
    }

    #[test]
    fn multiple_pending_entries_survive_when_incoming_loses_lww() {
        // (6) pending T1 + T3, incoming T2 → no apply (T2 < local T3), both entries survive.
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 3000, false, "local-latest"));
        enqueue_pending(&store, "n1", 1000);
        enqueue_pending(&store, "n1", 3000);
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote-middle")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 0, "incoming T2 < local T3 → no apply");
        assert!(res.superseded.is_empty());
        assert_eq!(
            store.outbox_items().unwrap().len(),
            2,
            "both pending entries survive"
        );
    }

    #[test]
    fn pull_does_not_panic_on_a_malformed_pending_payload() {
        // (7) malformed pending payload → left queued, pull succeeds, no conflict, no panic.
        let store = Store::open_in_memory().unwrap();
        apply_local(&store, "notes", note("n1", 1000, false, "local"));
        store.enqueue("notes", "n1", "not json", 1000).unwrap();
        let sink = MapSink::new().with("notes", vec![note("n1", 2000, false, "remote")]);

        let res = block(pull(&store, &sink, &["notes"])).unwrap();

        assert_eq!(res.merged, 1);
        assert!(
            res.superseded.is_empty(),
            "an unparseable entry can't be proven stale → not surfaced"
        );
        assert_eq!(
            store.outbox_items().unwrap().len(),
            1,
            "the malformed entry is left queued"
        );
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("remote")
        );
    }

    // ── SUR-737 array / row convergence ratification ──────────────────────────
    // pull_table is table-agnostic, so these pin the whole-row-LWW convergence of the composite
    // and row-per-pair tables. If a future change tries element-level merge (a `tags` union, a
    // `leaf_ids` union), these fail — the convergence contract on `store::synced_schema` is the
    // decision they enforce.

    #[test]
    fn sur737_tags_converge_whole_array_not_union() {
        // A tag set is whole-row LWW: the newer note's `tags` REPLACE the local ones, never union
        // (a union couldn't express a tag deletion). Both directions.
        let store = Store::open_in_memory().unwrap();

        // Local newer → an older remote loses; the local array is kept intact.
        apply_local(
            &store,
            "notes",
            json!({ "id": "n1", "tags": ["a", "b"], "updated_at": 2000, "deleted": false }),
        );
        let sink = MapSink::new().with(
            "notes",
            vec![json!({ "id": "n1", "tags": ["c"], "updated_at": 1000, "deleted": false })],
        );
        block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["tags"],
            json!(["a", "b"]),
            "older remote loses LWW; the local tag array is untouched"
        );

        // Remote newer → replaces the whole array; NOT the union ["a","b","c"].
        let sink = MapSink::new().with(
            "notes",
            vec![json!({ "id": "n1", "tags": ["c"], "updated_at": 3000, "deleted": false })],
        );
        block(pull(&store, &sink, &["notes"])).unwrap();
        assert_eq!(
            store.get_row("notes", "n1").unwrap().unwrap()["tags"],
            json!(["c"]),
            "newer remote replaces the whole tag array (no element union)"
        );
    }

    #[test]
    fn sur737_lens_leaf_ids_converge_whole_array_not_union() {
        // A lens is ONE authored query — its leaf_ids move whole-row LWW with the combinator +
        // threshold. Unioning leaves would fabricate a query nobody wrote.
        let store = Store::open_in_memory().unwrap();
        apply_local(
            &store,
            "lenses",
            json!({ "id": "l1", "name": "L", "leaf_ids": ["a", "b"], "combinator": "and", "threshold": 1, "updated_at": 1000, "deleted": false }),
        );
        let sink = MapSink::new().with(
            "lenses",
            vec![json!({ "id": "l1", "name": "L", "leaf_ids": ["c"], "combinator": "or", "threshold": 2, "updated_at": 2000, "deleted": false })],
        );
        block(pull(&store, &sink, &["lenses"])).unwrap();
        let row = store.get_row("lenses", "l1").unwrap().unwrap();
        assert_eq!(
            row["leaf_ids"],
            json!(["c"]),
            "newer lens replaces leaf_ids wholesale (no union)"
        );
        assert_eq!(
            row["combinator"],
            json!("or"),
            "the rest of the authored query moves with it"
        );
    }

    #[test]
    fn sur737_collection_membership_concurrent_adds_converge_then_tombstone() {
        // Memberships are row-per-pair with a DETERMINISTIC pk (membershipId(collection, note)), so
        // two devices adding the same pair share the same id → one row (OR-set add); a remove is a
        // tombstone on that row. (The shared pk + INSERT OR REPLACE is what collapses concurrent
        // adds — no duplicate row can exist.)
        let store = Store::open_in_memory().unwrap();
        let mid = "col1:note1"; // deterministic membershipId(collection, note)

        apply_local(
            &store,
            "collection_memberships",
            json!({ "id": mid, "collection_id": "col1", "note_id": "note1", "updated_at": 1000, "deleted": false }),
        );
        // Remote add of the SAME pair (same id) — merges onto the one row, not a second row.
        let sink = MapSink::new().with(
            "collection_memberships",
            vec![json!({ "id": mid, "collection_id": "col1", "note_id": "note1", "updated_at": 2000, "deleted": false })],
        );
        block(pull(&store, &sink, &["collection_memberships"])).unwrap();
        let row = store
            .get_row("collection_memberships", mid)
            .unwrap()
            .unwrap();
        assert_eq!(
            row["updated_at"],
            json!(2000_i64),
            "the newer add won the one row"
        );
        assert_eq!(row["deleted"], json!(false), "still a live membership");

        // A newer remove tombstones that row (OR-set remove).
        let sink = MapSink::new().with(
            "collection_memberships",
            vec![json!({ "id": mid, "collection_id": "col1", "note_id": "note1", "updated_at": 3000, "deleted": true })],
        );
        block(pull(&store, &sink, &["collection_memberships"])).unwrap();
        assert_eq!(
            store
                .get_row("collection_memberships", mid)
                .unwrap()
                .unwrap()["deleted"],
            json!(true),
            "a newer remove tombstones the membership"
        );
    }

    #[test]
    fn sur737_exact_ms_tie_keeps_local_so_replicas_can_diverge() {
        // Accepted residual (plan §8): the compare is strict `>`, so an exact-ms tie keeps local.
        // Two devices that wrote DIFFERENT values at the SAME updated_at do NOT converge — each keeps
        // its own after pulling the other. Pinned so a future tie-break becomes a deliberate,
        // wire-visible decision (PWA+core lockstep), not an accident. The convergence contract on
        // `store::synced_schema` carries this caveat.
        let dev_a = Store::open_in_memory().unwrap();
        let dev_b = Store::open_in_memory().unwrap();
        apply_local(&dev_a, "notes", note("n1", 5000, false, "value-A"));
        apply_local(&dev_b, "notes", note("n1", 5000, false, "value-B"));

        // A pulls B's row (same ts) → keeps A; B pulls A's row (same ts) → keeps B.
        let a_sees_b = MapSink::new().with("notes", vec![note("n1", 5000, false, "value-B")]);
        let b_sees_a = MapSink::new().with("notes", vec![note("n1", 5000, false, "value-A")]);
        block(pull(&dev_a, &a_sees_b, &["notes"])).unwrap();
        block(pull(&dev_b, &b_sees_a, &["notes"])).unwrap();

        assert_eq!(
            dev_a.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("value-A"),
            "device A keeps its own value on the tie"
        );
        assert_eq!(
            dev_b.get_row("notes", "n1").unwrap().unwrap()["text"],
            json!("value-B"),
            "device B keeps its own — ms-identical concurrent edit did NOT reconcile (accepted)"
        );
    }

    // ── SUR-726 fan-out: all eight tables + the non-`id` pk (note_signals) ─────

    #[test]
    fn sur726_all_eight_tables_pull_and_advance_cursors() {
        // Acceptance: every synced store incremental-pulls with its own cursor. One row per table
        // through a single `pull()` over the whole `synced_table_names()` scope.
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new()
            .with("books", vec![json!({ "id": "b1", "updated_at": 1000, "deleted": false })])
            .with("notes", vec![note("n1", 1000, false, "enc:v2:x")])
            .with(
                "custom_ideas",
                vec![json!({ "id": "ci1", "name": "I", "updated_at": 1000, "deleted": false })],
            )
            .with(
                "note_links",
                vec![json!({ "id": "nl1", "from_note_id": "n1", "to_note_id": "n1", "updated_at": 1000, "deleted": false })],
            )
            .with(
                "lenses",
                vec![json!({ "id": "l1", "name": "L", "leaf_ids": ["a"], "updated_at": 1000, "deleted": false })],
            )
            .with(
                "collections",
                vec![json!({ "id": "c1", "name": "C", "updated_at": 1000, "deleted": false })],
            )
            .with(
                "collection_memberships",
                vec![json!({ "id": "c1:n1", "note_id": "n1", "collection_id": "c1", "updated_at": 1000, "deleted": false })],
            )
            .with(
                "note_signals",
                vec![json!({ "note_id": "n1", "updated_at": 1000, "deleted": false })],
            );

        let tables = crate::store::synced_table_names();
        let res = block(pull(&store, &sink, &tables)).unwrap();

        assert_eq!(res.pulled, 8);
        assert_eq!(res.merged, 8);
        for (table, pk) in [
            ("books", "b1"),
            ("notes", "n1"),
            ("custom_ideas", "ci1"),
            ("note_links", "nl1"),
            ("lenses", "l1"),
            ("collections", "c1"),
            ("collection_memberships", "c1:n1"),
            ("note_signals", "n1"),
        ] {
            assert!(
                store.get_row(table, pk).unwrap().is_some(),
                "{table} row merged"
            );
            assert_eq!(
                store.get_seq_cursor(table).unwrap(),
                Some(1),
                "{table} cursor advanced to its one row's change_seq"
            );
        }
    }

    #[test]
    fn sur726_note_signals_pull_lww_keyed_by_note_id() {
        // note_signals is the one table whose pk is `note_id`, not `id`. Prove the full pull + LWW
        // path works keyed on it (the descriptor-driven pk[0] carries through end to end).
        let store = Store::open_in_memory().unwrap();
        apply_local(
            &store,
            "note_signals",
            json!({ "note_id": "n1", "return_visits": 1, "updated_at": 1000, "deleted": false }),
        );
        let sink = MapSink::new().with(
            "note_signals",
            vec![json!({ "note_id": "n1", "return_visits": 5, "updated_at": 2000, "deleted": false })],
        );
        let res = block(pull(&store, &sink, &["note_signals"])).unwrap();
        assert_eq!(res.merged, 1);
        assert_eq!(
            store.get_row("note_signals", "n1").unwrap().unwrap()["return_visits"],
            json!(5),
            "newer counters won whole-row LWW, keyed by note_id"
        );
    }

    #[test]
    fn sur726_note_signals_rebase_surfaces_superseded_by_note_id() {
        // The SUR-736 outbox rebase must fire on the non-`id` pk table too: a pending note_signals
        // edit that a newer remote row beats is dropped and surfaced, keyed by note_id.
        let store = Store::open_in_memory().unwrap();
        apply_local(
            &store,
            "note_signals",
            json!({ "note_id": "n1", "return_visits": 1, "updated_at": 1000, "deleted": false }),
        );
        store
            .enqueue(
                "note_signals",
                "n1",
                &json!({ "note_id": "n1", "return_visits": 1, "updated_at": 1000 }).to_string(),
                1000,
            )
            .unwrap();
        let sink = MapSink::new().with(
            "note_signals",
            vec![json!({ "note_id": "n1", "return_visits": 9, "updated_at": 2000, "deleted": false })],
        );

        let res = block(pull(&store, &sink, &["note_signals"])).unwrap();

        assert_eq!(res.merged, 1);
        assert_eq!(
            res.superseded,
            vec![SupersededEdit {
                table: "note_signals".into(),
                record_id: "n1".into(),
                discarded_updated_at: 1000,
                winning_updated_at: 2000,
            }]
        );
        assert!(
            store.outbox_items().unwrap().is_empty(),
            "the stale note_signals edit is rebased away"
        );
    }

    #[test]
    fn sur726_note_link_add_then_tombstone_and_bag_coexistence() {
        // note_links is row-per-edge (convergence contract): an add is an insert, a remove is a
        // tombstone (row-level LWW), and two DIFFERENT ids coexist (a "bag" — no dedup, unlike
        // memberships' deterministic pk).
        let store = Store::open_in_memory().unwrap();
        let sink = MapSink::new().with(
            "note_links",
            vec![
                json!({ "id": "nl1", "from_note_id": "a", "to_note_id": "b", "updated_at": 1000, "deleted": false }),
                json!({ "id": "nl2", "from_note_id": "a", "to_note_id": "b", "updated_at": 1000, "deleted": false }),
            ],
        );
        block(pull(&store, &sink, &["note_links"])).unwrap();
        assert!(store.get_row("note_links", "nl1").unwrap().is_some());
        assert!(
            store.get_row("note_links", "nl2").unwrap().is_some(),
            "same logical edge under a different id is a separate row (bag, no dedup)"
        );

        // A newer remove tombstones nl1 (row-level LWW remove).
        let sink = MapSink::new().with(
            "note_links",
            vec![json!({ "id": "nl1", "from_note_id": "a", "to_note_id": "b", "updated_at": 2000, "deleted": true })],
        );
        block(pull(&store, &sink, &["note_links"])).unwrap();
        assert_eq!(
            store.get_row("note_links", "nl1").unwrap().unwrap()["deleted"],
            json!(true),
            "a newer remove tombstones the edge"
        );
    }
}
