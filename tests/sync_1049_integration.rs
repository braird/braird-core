//! SUR-1049 — a BEHAVIOURAL round-trip against the native-first cloud tables
//! (`open_questions`, `question_note_overrides`, `user_settings`, SUR-1047's migration 0055).
//!
//! Why this exists, when `scripts/check-native-schema.mjs` already validates the same tables:
//! that check reads catalogues, and across five review rounds it accumulated thirteen findings of
//! one shape — **it confirms a thing EXISTS where what matters is whether it WORKS**. A column is
//! present but the server cannot stamp it; RLS is enabled but no policy covers INSERT; a trigger is
//! named `change_seq` but is DISABLED, or fires AFTER, or never assigns `NEW.change_seq`; a type
//! matches logically but is too narrow to hold an epoch millisecond. Introspection can only ever
//! enumerate the mistakes someone already thought of.
//!
//! So this executes the path instead. Every one of those thirteen fails here naturally: a missing
//! or misfiring trigger leaves `change_seq` null and the stamp assertion fails; a too-narrow int
//! fails the insert on numeric range; a `uuid` id rejects the deterministic `question_id:note_id`;
//! a SELECT-only policy set fails the insert; a `NOT NULL` cloud-only column fails the insert; a
//! permissive `WITH CHECK` fails the isolation assertion.
//!
//! **Raw PostgREST, not the sync engine — deliberately (SUR-1049 decision).** These tables are
//! registered but not yet wired: `store::table_schema()` and `synced_table_names()` exclude them
//! until SUR-1042 defines their encryption boundary, so `enqueue_* → flush` has no path for them
//! yet. Probing the wire directly proves the CLOUD side before core code is built on top of it —
//! and SUR-1042 upgrades these same assertions to run through the real outbox.
//!
//! **Local ephemeral stack only.** `sync-integration.yml` replays surfc's migrations (including
//! 0055) into a throwaway Supabase, so there is no test-user provisioning policy and no teardown
//! obligation — the whole database dies with the job. The complementary question, "is the migration
//! actually APPLIED to braird-staging", is what the introspection leg already answers; the two
//! cover behaviour and deployment with no overlap and no writes to a shared database.
//!
//! Native-only, and `#[ignore]`d + env-guarded exactly like the sibling integration tests: a bare
//! `cargo test` with no stack skips it rather than failing.
#![cfg(not(target_arch = "wasm32"))]

use serde_json::json;

/// Epoch **milliseconds**, the wire convention for every synced table. Deliberately larger than
/// `i32::MAX` (2.1e9): if a migration ever declares one of these columns `integer`, the insert
/// fails here on numeric range — the failure the logical-type compare cannot see.
const TS: i64 = 1_777_000_000_000;

/// The `change_seq` of the single row matching `query`, or `None` if the row is not visible.
/// Read as an i64 so a null (never stamped) is distinguishable from a zero.
fn change_seq_of(
    env: &test_support::SupabaseEnv,
    token: &str,
    table: &str,
    query: &str,
) -> Option<i64> {
    let rows = test_support::select(env, token, table, query);
    let row = rows.as_array().expect("rows array").first()?;
    // A NULL change_seq — the never-stamped case — reads back as 0 rather than panicking here.
    // Panicking would report "not an integer" in precisely the failure this test exists to catch,
    // burying the caller's `seq > 0` message that actually explains it (raised on review).
    Some(row["change_seq"].as_i64().unwrap_or(0))
}

#[test]
#[ignore = "needs a running local Supabase stack (CI `integration` job, or a local `supabase start`)"]
fn native_tables_accept_writes_stamp_change_seq_and_isolate_users() {
    let Some(env) = test_support::env() else {
        eprintln!("SUPABASE_URL unset — skipping the SUR-1049 round-trip");
        return;
    };

    let a = test_support::mint_test_user_jwt(&env);
    let b = test_support::mint_test_user_jwt(&env);
    let (uid, tok) = (a.user_id.clone(), a.access_token.clone());

    let q_id = format!("q-{uid}");
    let note_id = format!("n-{uid}");
    // The deterministic pk SUR-1048 locked: `question_id:note_id`, NOT a uuid. If migration 0055
    // ever declared this column `uuid`, this insert is where it fails.
    let ov_id = format!("{q_id}:{note_id}");

    // ── 1. INSERT through PostgREST as a real user ───────────────────────────────────────────
    // Reaching the table at all requires: an INSERT policy covering `authenticated` (RLS denies
    // any command no policy grants), a WITH CHECK the row satisfies, and every NOT NULL column
    // either supplied here or filled by the server.
    test_support::upsert(
        &env,
        &tok,
        "open_questions",
        "id",
        &json!([{
            "id": q_id, "user_id": uid,
            "text": "enc:v2:aXY=.Y3Q=",           // opaque ciphertext — the server never reads it
            "status": "live", "tone": "introspective",
            "created_at": TS, "updated_at": TS, "deleted": false
        }]),
    );
    test_support::upsert(
        &env,
        &tok,
        "user_settings",
        "user_id,key",
        &json!([{ "user_id": uid, "key": "prompt_cadence", "value": "168", "updated_at": TS, "deleted": false }]),
    );
    // question_note_overrides FKs both open_questions(id) and notes(id), so the note must exist
    // first — a real one, owned by the same user, or the FK rejects with 23503.
    test_support::upsert(
        &env,
        &tok,
        "notes",
        "id",
        &json!([{
            "id": note_id, "user_id": uid, "text": "enc:v2:aXY=.Y3Q=",
            "created_at": TS, "updated_at": TS, "deleted": false
        }]),
    );
    test_support::upsert(
        &env,
        &tok,
        "question_note_overrides",
        "id",
        &json!([{
            "id": ov_id, "user_id": uid, "question_id": q_id, "note_id": note_id,
            "kind": "include", "created_at": TS, "updated_at": TS, "deleted": false
        }]),
    );

    // ── 2. The rows come back, and change_seq was STAMPED ────────────────────────────────────
    // The column existing is not the property under test: `upsert` never sends change_seq, so a
    // non-null value here can only have come from the server-side trigger. A trigger that is
    // disabled, AFTER, statement-level, DELETE-only, or whose function returns NEW without
    // assigning it, all land as null — and a null is invisible to `change_seq=gt.<cursor>`, i.e.
    // a row that syncs to nobody, forever.
    let seqs: Vec<(&str, String, i64)> = [
        ("open_questions", format!("id=eq.{q_id}")),
        ("question_note_overrides", format!("id=eq.{ov_id}")),
        ("user_settings", "key=eq.prompt_cadence".to_string()),
    ]
    .into_iter()
    .map(|(table, query)| {
        let seq = change_seq_of(&env, &tok, table, &query)
            .unwrap_or_else(|| panic!("{table}: the row just written is not readable back"));
        assert!(
            seq > 0,
            "{table}: change_seq is {seq} — the stamping trigger did not fire on INSERT, so this \
             row is invisible to every pull (change_seq=gt.N excludes it)"
        );
        (table, query, seq)
    })
    .collect();

    // ── 3. UPDATE re-stamps — on EVERY table ─────────────────────────────────────────────────
    // The watermark must ADVANCE on edit too, or an updated row never re-delivers to another
    // device. This is the half a BEFORE INSERT-only trigger passes step 2 with — and per table,
    // because each `t02_change_seq` is a SEPARATE trigger definition: one created without the
    // UPDATE event, or bound to a different function, is invisible to a check that only ever
    // edits `open_questions` (raised on review).
    //
    // Every payload bumps `updated_at`. `t01_lww_guard` fires BEFORE UPDATE and cancels
    // (RETURN NULL) a write that is not strictly newer, which would skip the stamp and read as a
    // trigger failure here rather than the LWW guard doing its job.
    for (table, on_conflict, row) in [
        (
            "open_questions",
            "id",
            json!({
                "id": q_id, "user_id": uid, "text": "enc:v2:aXY=.Y3Q3",
                "status": "resolved", "resolved_at": TS + 1,
                "created_at": TS, "updated_at": TS + 1, "deleted": false
            }),
        ),
        (
            "question_note_overrides",
            "id",
            json!({
                "id": ov_id, "user_id": uid, "question_id": q_id, "note_id": note_id,
                "kind": "exclude", "created_at": TS, "updated_at": TS + 1, "deleted": false
            }),
        ),
        (
            "user_settings",
            "user_id,key",
            json!({
                "user_id": uid, "key": "prompt_cadence", "value": "336",
                "updated_at": TS + 1, "deleted": false
            }),
        ),
    ] {
        test_support::upsert(&env, &tok, table, on_conflict, &json!([row]));

        let (_, query, before) = seqs
            .iter()
            .find(|(t, _, _)| *t == table)
            .expect("table captured in step 2");
        let after = change_seq_of(&env, &tok, table, query)
            .unwrap_or_else(|| panic!("{table}: row not readable after update"));
        assert!(
            after > *before,
            "{table}: change_seq did not advance on UPDATE ({before} → {after}) — an edited row \
             would never re-deliver to another device"
        );
    }

    // ── 4. A SECOND USER SEES NOTHING ────────────────────────────────────────────────────────
    // The tenant boundary, executed rather than inferred. `get_page` sends NO user_id filter, so
    // RLS is the only thing separating these users. A `USING (true)` policy passes every
    // catalogue check and fails right here.
    for (table, query, _) in &seqs {
        let rows = test_support::select(&env, &b.access_token, table, query);
        assert_eq!(
            rows.as_array().map(Vec::len),
            Some(0),
            "{table}: user B can read user A's row — RLS is not isolating tenants"
        );
    }

    // ── 4b. B SEEDS ROWS IT LEGITIMATELY OWNS ────────────────────────────────────────────────
    // Needed before the write probes below: an override claiming A's user_id must reference
    // parents B CAN see, or the policy's EXISTS clauses reject it and mask the ownership
    // predicate that is actually under test (raised on review). These rows are also what step 6
    // attempts to transfer.
    let (b_uid, b_tok) = (b.user_id.clone(), b.access_token.clone());
    let (b_q, b_n) = (format!("q-{b_uid}"), format!("n-{b_uid}"));
    let b_ov = format!("{b_q}:{b_n}");

    for (table, on_conflict, row) in [
        (
            "open_questions",
            "id",
            json!({
                "id": b_q, "user_id": b_uid, "text": "enc:v2:aXY=.Y3Q=", "status": "live",
                "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            "notes",
            "id",
            json!({
                "id": b_n, "user_id": b_uid, "text": "enc:v2:aXY=.Y3Q=",
                "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            "question_note_overrides",
            "id",
            json!({
                "id": b_ov, "user_id": b_uid, "question_id": b_q, "note_id": b_n,
                "kind": "include", "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            "user_settings",
            "user_id,key",
            json!({
                // A key A does NOT hold. Reusing `prompt_cadence` would make the transfer
                // target collide with A's existing (user_id, key), so a 409 would satisfy the
                // assertion below without RLS having rejected anything.
                "user_id": b_uid, "key": "prompt_tone", "value": "72",
                "updated_at": TS, "deleted": false
            }),
        ),
    ] {
        test_support::upsert(&env, &b_tok, table, on_conflict, &json!([row]));
    }

    // ── 5. AND CANNOT WRITE ON A'S BEHALF — on EVERY table ───────────────────────────────────
    // The write half of the boundary, which a scoped USING with a permissive WITH CHECK leaves
    // wide open while every read assertion above still passes.
    //
    // Probing only one table would leave the other two uncovered by BOTH layers: a
    // `WITH CHECK (auth.uid() = user_id OR true)` on `user_settings` also satisfies
    // check-native-schema.mjs, which only searches the predicate for the `auth.uid()` substring
    // (raised on review). So each table gets its own cross-owner attempt.
    for (table, on_conflict, row) in [
        (
            "open_questions",
            "id",
            json!({
                "id": format!("intruder-{uid}"), "user_id": uid,
                "text": "enc:v2:aXY=.Y3Q=", "status": "live",
                "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            // B-OWNED parents, deliberately. Pointing at A's question and note would make the
            // policy's EXISTS clauses reject this (B cannot see A's rows) — and those clauses
            // would then mask a weakened `auth.uid() = user_id`, leaving the test green for the
            // exact ownership regression it exists to catch (raised on review). With parents B
            // can see, the EXISTS clauses pass and ownership is the only thing left to reject it.
            "question_note_overrides",
            "id",
            json!({
                "id": format!("intruder:{b_ov}"), "user_id": uid,
                "question_id": b_q, "note_id": b_n, "kind": "include",
                "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            // The per-user KV: B claiming A's user_id is the two-account collision SUR-1047's
            // composite key exists to make impossible.
            //
            // A key A has NOT written, deliberately. Targeting the existing `prompt_cadence`
            // would collide, and `resolution=merge-duplicates` then takes the ON CONFLICT DO
            // UPDATE path — where UPDATE's USING (which B fails, not seeing A's row) rejects it.
            // The request 4xx's either way, so a permissive INSERT `WITH CHECK` would slip past
            // while B could still create a NEW setting owned by A (raised on review). A
            // non-conflicting key forces the INSERT policy to be the thing under test.
            "user_settings",
            "user_id,key",
            json!({
                "user_id": uid, "key": "prompt_tone", "value": "hijacked",
                "updated_at": TS + 2, "deleted": false
            }),
        ),
    ] {
        let status =
            test_support::try_upsert(&env, &b.access_token, table, on_conflict, &json!([row]));
        assert!(
            status.is_client_error(),
            "{table}: user B wrote a row owned by user A (HTTP {status}) — the WITH CHECK \
             predicate is not scoping writes, even though reads are correctly fenced"
        );
    }

    // A rejected write must leave nothing behind — checked from A's side, since B cannot see
    // these rows either way and a status code alone does not prove nothing was written.
    // The row B tried to CREATE for A must not exist...
    let planted = test_support::select(&env, &tok, "user_settings", "key=eq.prompt_tone");
    assert_eq!(
        planted.as_array().map(Vec::len),
        Some(0),
        "user_settings: user B created a setting owned by user A — the INSERT policy's WITH CHECK \
         is not scoping writes"
    );
    // ...and the row it tried to overwrite must still hold A's own last write (step 3's value).
    let settings = test_support::select(&env, &tok, "user_settings", "key=eq.prompt_cadence");
    assert_eq!(
        settings[0]["value"], "336",
        "user_settings: user A's value changed after B's rejected write"
    );

    // ── 6. NOR TRANSFER ITS OWN ROWS TO A ────────────────────────────────────────────────────
    // Every probe above targets a key that does not exist yet, so they all take the INSERT path
    // and exercise only the INSERT policy. An UPDATE is a separate RLS decision — `USING` picks
    // which rows may be changed, `WITH CHECK` decides what they may become — so a permissive
    // `WITH CHECK` on UPDATE alone would pass everything so far while letting B rewrite one of
    // its OWN rows to carry A's user_id, planting data in A's account (raised on review).
    //
    // B therefore seeds rows it legitimately owns, then attempts the ownership transfer. `USING`
    // passes (B owns them), so the request reaches `WITH CHECK` — which is the predicate under
    // test. A 2xx here means the transfer succeeded.

    for (table, query) in [
        ("open_questions", format!("id=eq.{b_q}")),
        ("question_note_overrides", format!("id=eq.{b_ov}")),
        ("user_settings", "key=eq.prompt_tone".to_string()),
    ] {
        let status = test_support::try_patch(
            &env,
            &b_tok,
            table,
            &query,
            &json!({ "user_id": uid, "updated_at": TS + 3 }),
        );
        assert!(
            status.is_client_error(),
            "{table}: user B reassigned its own row to user A (HTTP {status}) — UPDATE's WITH \
             CHECK is not scoping ownership, so B can plant rows in A's account"
        );

        // And nothing landed in A's account regardless of what the status said.
        let planted = test_support::select(&env, &tok, table, &query);
        assert_eq!(
            planted.as_array().map(Vec::len),
            Some(0),
            "{table}: a row owned by user B is now visible to user A"
        );
    }
}
