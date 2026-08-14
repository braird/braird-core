//! Schema-drift parity (SUR-723 §7) + the native-first schema lock (SUR-1048).
//!
//! Two fixtures, two directions of authority:
//!
//!   - `vendored/schema/sync-schema.json` is DERIVED from `surfc/main` (`supabase.js`'s `upsert*`
//!     payloads for the synced column set, the migrations for the logical types, via
//!     `scripts/extract-sync-schema.mjs`). surfc is the source of truth; drift means the native
//!     mirror fell behind. `.github/workflows/schema-drift.yml` re-derives the fixture in CI, so a
//!     new synced column in surfc cannot silently desync the native store (the `content_tag` case).
//!
//!   - `vendored/schema/native-schema.json` is HAND-AUTHORED and LOCKS [`native_schema`] (SUR-1048).
//!     These tables are native-first — no PWA counterpart exists to derive from — so this
//!     descriptor IS the source of truth and the fixture exists to make every shape change a
//!     deliberate two-file diff. `scripts/check-native-schema.mjs` closes the remaining gap by
//!     asserting the fixture matches the DDL actually applied to `braird-staging`.
//!
//! The third test is the one that keeps the registry honest: **every** table the live store creates
//! must appear in exactly one of the two fixtures or the local-only list. Without it a new table
//! could simply be created and belong to no contract at all — which is how a waiver list rots, and
//! the reason SUR-1048 rejected one.
//!
//! Native-only: the store (rusqlite) is gated off wasm32.
#![cfg(not(target_arch = "wasm32"))]

use braird_core::store::{
    native_schema, synced_schema, synced_table_names, table_schema, Store, TableSchema,
    LOCAL_ONLY_TABLES,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Schema = BTreeMap<String, BTreeMap<String, String>>;

/// `{ table → { column → logical-type } }` from a vendored fixture.
fn fixture_schema(file: &str) -> Schema {
    let path = format!("{}/vendored/schema/{file}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let json: Value = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    json.as_object()
        .unwrap_or_else(|| panic!("{path} is not an object"))
        .iter()
        .map(|(table, cols)| {
            let cols = cols
                .as_object()
                .unwrap_or_else(|| panic!("{table} is not an object"))
                .iter()
                .map(|(c, ty)| {
                    (
                        c.clone(),
                        ty.as_str().expect("logical type is a string").to_string(),
                    )
                })
                .collect();
            (table.clone(), cols)
        })
        .collect()
}

/// The same shape from a core descriptor.
fn descriptor_schema(tables: &'static [TableSchema]) -> Schema {
    tables
        .iter()
        .map(|t| {
            let cols = t
                .columns
                .iter()
                .map(|(name, ty)| (name.to_string(), ty.logical().to_string()))
                .collect();
            (t.name.to_string(), cols)
        })
        .collect()
}

/// Reconcile a descriptor against its fixture in both directions: same table set, then same
/// `(column → logical-type)` per table. `remedy` is the fix instruction printed on failure —
/// it differs per fixture because the two have opposite sources of truth.
fn assert_reconciles(core: &Schema, fixture: &Schema, remedy: &str) {
    let core_tables: Vec<&String> = core.keys().collect();
    let fixture_tables: Vec<&String> = fixture.keys().collect();
    assert_eq!(
        core_tables, fixture_tables,
        "table set diverged from the vendored fixture — {remedy}"
    );

    for (table, fixture_cols) in fixture {
        let core_cols = core.get(table).expect("table present in core");
        assert_eq!(
            core_cols, fixture_cols,
            "column set / types for `{table}` diverged from the vendored fixture — {remedy}"
        );
    }
}

#[test]
fn core_synced_schema_matches_vendored_fixture() {
    // The silent-desync guard: a column in the fixture (= surfc's synced set) but missing or
    // retyped in the core fails here.
    assert_reconciles(
        &descriptor_schema(synced_schema()),
        &fixture_schema("sync-schema.json"),
        "re-run scripts/extract-sync-schema.mjs and update synced_schema() in src/store.rs",
    );
}

#[test]
fn core_native_schema_matches_vendored_fixture() {
    // A LOCK, not a derivation (SUR-1048): nothing upstream can be re-derived to settle a
    // disagreement, so the two files must be changed together, deliberately, in one reviewable diff.
    assert_reconciles(
        &descriptor_schema(native_schema()),
        &fixture_schema("native-schema.json"),
        "native_schema() in src/store.rs and vendored/schema/native-schema.json must change \
         together; if the shape really changed, update vendored/schema/native-manifest.json and \
         SUR-1047's migration too",
    );
}

#[test]
fn native_primary_keys_match_the_manifest() {
    // The column-only compare above is blind to the KEY, and for these tables the key is not
    // bookkeeping: `question_note_overrides`'s deterministic `question_id:note_id` id is what makes
    // two devices curating the same pair converge to ONE row instead of two contradictory ones, and
    // `user_settings` is keyed per SETTING so one device's cadence change cannot stomp another key.
    // SUR-1047 authors its migration from this contract, so a wrong key would be invented there and
    // caught by nothing (raised on review; the SUR-723 sibling defers PK coverage on the grounds
    // that a surfc PK change is a breaking cloud migration — an assumption native-first voids,
    // since the cloud table does not exist yet).
    let manifest = std::fs::read_to_string(format!(
        "{}/vendored/schema/native-manifest.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read native-manifest.json");
    let manifest: Value = serde_json::from_str(&manifest).expect("parse native-manifest.json");
    let rows = manifest["entries"].as_array().expect("entries array");

    for t in native_schema() {
        let row = rows
            .iter()
            .find(|r| r["table"] == t.name)
            .unwrap_or_else(|| panic!("no native-manifest.json row for `{}`", t.name));
        let declared: Vec<String> = row["pk"]
            .as_array()
            .unwrap_or_else(|| panic!("`{}` row has no \"pk\" array", t.name))
            .iter()
            .map(|c| c.as_str().expect("pk column is a string").to_string())
            .collect();
        let actual: Vec<String> = t.pk.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            actual, declared,
            "primary key for `{}` diverged between native_schema() and native-manifest.json",
            t.name
        );

        // A pk column that is not in the table is a typo the DDL check would only surface against
        // staging — much later, and only once the migration lands.
        for col in &actual {
            assert!(
                t.columns.iter().any(|(name, _)| name == col),
                "`{}` declares pk column `{col}`, which is not one of its columns",
                t.name
            );
        }
    }
}

#[test]
fn native_tables_are_registered_but_not_yet_writable_or_pulled() {
    // The seal boundary is currently enforced by ABSENCE — native-first tables are simply missing
    // from `table_schema()` and the pull scope. Absence is invisible: nothing breaks if a future
    // change quietly resolves them, and `apply_row` would then write `questions` with no
    // encryption contract (plaintext question text reaching SQLite is the crypto-reviewer BLOCKER
    // class). This pins the gap so SUR-1042 has to DELETE a failing test to open the path —
    // a deliberate act with a reviewer attached — rather than widening a lookup and moving on.
    for t in native_schema() {
        assert!(
            table_schema(t.name).is_none(),
            "`{}` resolves via table_schema(), which makes apply_row/get_row write it. If SUR-1042 \
             is wiring the sync legs, delete this assertion in the same commit that lands the \
             encryption boundary — not before",
            t.name
        );
        assert!(
            !synced_table_names().contains(&t.name),
            "`{}` is in the pull scope, but its cloud table only exists once SUR-1047's migration \
             lands — every pull would 404 until then",
            t.name
        );
    }
}

#[test]
fn every_store_table_is_registered_in_exactly_one_contract() {
    let synced = fixture_schema("sync-schema.json");
    let native = fixture_schema("native-schema.json");

    // EXACTLY one, checked before deduping. Collecting straight into a set would collapse a table
    // claimed by two contracts and let the union comparison below pass — so the duplicate check runs
    // on the flat list, across all three contracts at once (not just synced-vs-native: a table in
    // both a fixture and LOCAL_ONLY_TABLES is the same lie, and would mean a synced table silently
    // exempted from the drift guard).
    let claimed: Vec<String> = synced
        .keys()
        .chain(native.keys())
        .cloned()
        .chain(LOCAL_ONLY_TABLES.iter().map(|s| s.to_string()))
        .collect();
    let registered: BTreeSet<String> = claimed.iter().cloned().collect();
    assert_eq!(
        claimed.len(),
        registered.len(),
        "a table is claimed by more than one contract. Each must appear in exactly ONE of \
         vendored/schema/sync-schema.json (derived from surfc), vendored/schema/native-schema.json \
         (native-first), or store::LOCAL_ONLY_TABLES (device-local) — claimed: {claimed:?}"
    );

    // Ask SQLite, not the descriptors: a descriptor-driven list is blind to a table created by raw
    // DDL (LOCAL_ONLY_DDL), which is exactly the gap an unregistered table would slip through.
    let live: BTreeSet<String> = Store::open_in_memory()
        .expect("open in-memory store")
        .table_names()
        .expect("read sqlite_master")
        .into_iter()
        .collect();

    let unregistered: Vec<&String> = live.difference(&registered).collect();
    assert!(
        unregistered.is_empty(),
        "store table(s) {unregistered:?} belong to no contract. Every table must be registered in \
         exactly one of: vendored/schema/sync-schema.json (derived from surfc), \
         vendored/schema/native-schema.json + native-manifest.json (native-first, SUR-1048), or \
         store::LOCAL_ONLY_TABLES (device-local, never synced)"
    );

    let missing: Vec<&String> = registered.difference(&live).collect();
    assert!(
        missing.is_empty(),
        "table(s) {missing:?} are registered but the store never creates them — a fixture or \
         LOCAL_ONLY_TABLES row outlived its table"
    );
}
