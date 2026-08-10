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

use braird_core::store::{native_schema, synced_schema, Store, TableSchema, LOCAL_ONLY_TABLES};
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
fn every_store_table_is_registered_in_exactly_one_contract() {
    let synced = fixture_schema("sync-schema.json");
    let native = fixture_schema("native-schema.json");

    // No table may be claimed by both fixtures — "exactly one" is what makes the partition
    // meaningful, and a surfc-derived table quietly copied into the hand-authored fixture would
    // escape re-derivation in schema-drift.yml.
    let overlap: Vec<&String> = native.keys().filter(|t| synced.contains_key(*t)).collect();
    assert!(
        overlap.is_empty(),
        "table(s) {overlap:?} are in BOTH vendored/schema/sync-schema.json and native-schema.json \
         — a table is either derived from surfc or native-first, never both"
    );

    let registered: BTreeSet<String> = synced
        .keys()
        .chain(native.keys())
        .cloned()
        .chain(LOCAL_ONLY_TABLES.iter().map(|s| s.to_string()))
        .collect();

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
