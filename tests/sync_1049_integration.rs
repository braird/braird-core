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

use serde_json::{json, Value};

/// Epoch **milliseconds**, the wire convention for every synced table. Deliberately larger than
/// `i32::MAX` (2.1e9): if a migration ever declares one of these columns `integer`, the insert
/// fails here on numeric range — the failure the logical-type compare cannot see.
const TS: i64 = 1_777_000_000_000;

/// `upsert` that returns the HTTP status instead of panicking — the isolation assertions need to
/// observe a REJECTED write, which `test_support::upsert` turns into a panic.
fn try_upsert(
    env: &test_support::SupabaseEnv,
    access_token: &str,
    table: &str,
    on_conflict: &str,
    rows: &Value,
) -> reqwest::StatusCode {
    reqwest::blocking::Client::new()
        .post(format!(
            "{}/rest/v1/{}?on_conflict={}",
            env.url, table, on_conflict
        ))
        .header("apikey", &env.anon_key)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .header("Prefer", "resolution=merge-duplicates")
        .json(rows)
        .send()
        .expect("upsert send")
        .status()
}

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
    Some(row["change_seq"].as_i64().unwrap_or_else(|| {
        panic!(
            "{table}: change_seq is not an integer: {}",
            row["change_seq"]
        )
    }))
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

    // ── 3. UPDATE re-stamps ──────────────────────────────────────────────────────────────────
    // The watermark must ADVANCE on edit too, or an updated row never re-delivers to other
    // devices. This is the half a BEFORE INSERT-only trigger passes step 2 with.
    test_support::upsert(
        &env,
        &tok,
        "open_questions",
        "id",
        &json!([{
            "id": q_id, "user_id": uid, "text": "enc:v2:aXY=.Y3Q3",
            "status": "resolved", "resolved_at": TS + 1,
            "created_at": TS, "updated_at": TS + 1, "deleted": false
        }]),
    );
    let before = seqs
        .iter()
        .find(|(t, _, _)| *t == "open_questions")
        .map(|(_, _, s)| *s)
        .expect("open_questions seq");
    let after = change_seq_of(&env, &tok, "open_questions", &format!("id=eq.{q_id}"))
        .expect("row still readable after update");
    assert!(
        after > before,
        "open_questions: change_seq did not advance on UPDATE ({before} → {after}) — an edited \
         row would never re-deliver to another device"
    );

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
            // Referencing A's question and note deliberately: FK checks bypass RLS, so the only
            // things that can reject this are the ownership predicate and the policy's EXISTS
            // clauses (which, evaluated as B, cannot see A's rows).
            "question_note_overrides",
            "id",
            json!({
                "id": format!("intruder:{ov_id}"), "user_id": uid,
                "question_id": q_id, "note_id": note_id, "kind": "include",
                "created_at": TS, "updated_at": TS, "deleted": false
            }),
        ),
        (
            // The per-user KV: B claiming A's (user_id, key) pair is the two-account collision
            // SUR-1047's composite key exists to make impossible.
            "user_settings",
            "user_id,key",
            json!({
                "user_id": uid, "key": "prompt_cadence", "value": "hijacked",
                "updated_at": TS + 2, "deleted": false
            }),
        ),
    ] {
        let status = try_upsert(&env, &b.access_token, table, on_conflict, &json!([row]));
        assert!(
            status.is_client_error(),
            "{table}: user B wrote a row owned by user A (HTTP {status}) — the WITH CHECK \
             predicate is not scoping writes, even though reads are correctly fenced"
        );
    }

    // And A's data is untouched by those attempts — a rejected write must not have partially
    // applied. `value` is the one field the intruder tried to overwrite.
    let settings = test_support::select(&env, &tok, "user_settings", "key=eq.prompt_cadence");
    assert_eq!(
        settings[0]["value"], "168",
        "user_settings: user A's value changed after B's rejected write"
    );
}
