#!/usr/bin/env node
// check-native-schema — prove the native-first schema lock against the DDL actually applied to
// braird-staging (SUR-1048).
//
// `vendored/schema/sync-schema.json` is DERIVED from surfc, so `schema-drift.yml` can re-derive it
// and catch drift by construction. The native-first tables (SUR-996: open_questions,
// question_note_overrides, user_settings) have no PWA counterpart — `src/store.rs`'s
// `native_schema()` IS the source of truth and `vendored/schema/native-schema.json` is a
// hand-authored LOCK of it. `tests/schema_parity.rs` reconciles those two.
//
// That leaves exactly one gap this script closes: **the cloud side.** A migration can be written,
// reviewed, merged and never applied — or applied with a different type — and nothing in the Rust
// build would notice, because there is nothing upstream to re-derive from. So we ask the database.
//
// Two checks (fail-loud, no silent fallback — ADR 0001 discipline):
//   (a) MANIFEST — every fixture table has exactly one `native-manifest.json` row, no orphans,
//       every row names an owning ticket, and a `pending` row names the backend ticket.
//   (b) DDL — for each `backend: live` table, every fixture column exists in braird-staging with a
//       matching logical type, and row-level security is ENABLED. For each `backend: pending`
//       table, the table must be ABSENT — finding it means the migration landed and the row is
//       stale, which fails with "flip it to live". That is what stops `pending` from rotting into
//       a permanent, silent exemption (the waiver-list failure mode SUR-1048 rejected).
//
// SUBSET, not equality, on columns: the cloud legitimately carries columns the local mirror never
// stores — `user_id` (auth-injected at push, never persisted locally) and `change_seq` (the
// server-assigned watermark from surfc migration 0051). Cloud-only columns are reported as a
// notice, not a failure, matching the additive-nullable column contract `apply_row` already
// projects unknown columns out under. A fixture column MISSING from the cloud, or retyped, fails.
//
// This is CI tooling, not crate code: pure Node + the `psql` client (preinstalled on
// ubuntu-latest), no npm dependency, the Rust core is untouched. Sibling of
// scripts/check-native-parity.mjs.
//
// Usage: BRAIRD_STAGING_DB_URL=postgres://... node scripts/check-native-schema.mjs --check
//   The connection string is read from the environment ONLY — never a CLI arg, never logged, and
//   redacted out of any psql error before it reaches the CI log. Fails closed when unset: a schema
//   gate that passes because a secret went missing is worse than no gate at all.
//
//   The role in that URL must be able to SEE the registered tables: `information_schema.columns` is
//   privilege-filtered, while the `pg_class` half is not. A role without access therefore reports a
//   live table's columns as all-missing, or a pending table as "present but empty" — both LOUD
//   failures rather than silent passes, but confusing ones, so use a role with read access to
//   `public` (the migration/service role, not an anon key).

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { logicalType } from './logical-type.mjs';

const FIXTURE = 'vendored/schema/native-schema.json';
const MANIFEST = 'vendored/schema/native-manifest.json';
const DB_URL_ENV = 'BRAIRD_STAGING_DB_URL';

const VALID_BACKEND = new Set(['live', 'pending']);
const TICKET_RE = /^SUR-\d+$/;
// A table identifier we are willing to interpolate into SQL. The names come from our own
// checked-in fixture, but a gate that builds SQL from a file should still refuse anything that
// isn't a plain identifier.
const IDENT_RE = /^[a-z_][a-z0-9_]*$/;

// Columns the cloud has and the local mirror deliberately never stores. Named so the notice about
// cloud-only columns stays signal: these two are expected on every table.
const SERVER_ONLY_COLUMNS = new Set(['user_id', 'change_seq']);

const readJson = (path) => {
  const raw = readFileSync(path, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`parse ${path}: ${e.message}`);
  }
};

// --- (a) MANIFEST -----------------------------------------------------------------
// Returns the rows keyed by table. Rows with problems are still returned — every finding is
// accumulated rather than thrown, so one bad row cannot hide the rest — but a row whose `backend`
// is not live|pending is skipped by the DDL leg, which never guesses at a half-valid row.
export function checkManifest(fixture, errors, manifest = readJson(MANIFEST)) {
  if (!Array.isArray(manifest.entries)) throw new Error(`${MANIFEST} has no \`entries\` array`);

  const rows = new Map();
  for (const row of manifest.entries) {
    const where = `${MANIFEST} row "${row.table ?? '(missing table)'}"`;
    if (!row.table) {
      errors.push(`${where}: missing "table".`);
      continue;
    }
    if (rows.has(row.table)) {
      errors.push(`${where}: duplicate row — one row per table.`);
      continue;
    }
    rows.set(row.table, row);

    if (!(row.table in fixture)) {
      errors.push(`${where} is not a table in ${FIXTURE} — remove it, or add the table's shape.`);
    }
    if (!TICKET_RE.test(row.ticket ?? '')) {
      errors.push(`${where}: REQUIRES a "ticket" matching SUR-nnn (who owns this table's shape).`);
    }
    if (!VALID_BACKEND.has(row.backend)) {
      errors.push(`${where}: backend "${row.backend}" is not one of live|pending.`);
      continue;
    }
    if (row.backend === 'pending' && !TICKET_RE.test(row.backend_ticket ?? '')) {
      errors.push(
        `${where}: a "pending" row REQUIRES a "backend_ticket" (SUR-nnn) — the migration that will ` +
          `create it. Pending means "tracked gap", never "unchecked forever".`
      );
    }
  }

  for (const table of Object.keys(fixture)) {
    if (!rows.has(table)) {
      errors.push(
        `${FIXTURE} table "${table}" has no row in ${MANIFEST}.\n` +
          `  Add: { "table": "${table}", "ticket": "SUR-nnn", "backend": "live|pending", ` +
          `"backend_ticket": "SUR-nnn", "note": "..." }`
      );
    }
  }
  return rows;
}

// --- braird-staging introspection --------------------------------------------------
function queryStaging(tables) {
  const url = process.env[DB_URL_ENV];
  if (!url) {
    throw new Error(
      `${DB_URL_ENV} is not set — cannot reach braird-staging.\n` +
        `  This check fails closed on purpose: a green schema gate that never opened a connection ` +
        `is worse than no gate. Set the secret (CI) or export it locally.`
    );
  }
  for (const t of tables) {
    if (!IDENT_RE.test(t)) throw new Error(`refusing to query non-identifier table name: "${t}"`);
  }
  const list = tables.map((t) => `'${t}'`).join(', ');

  // One round trip: the column shapes plus each table's rowsecurity flag, as one JSON document.
  const sql = `
    SELECT json_build_object(
      'columns', (
        SELECT coalesce(json_agg(json_build_object(
          'table', table_name, 'column', column_name, 'data_type', data_type, 'udt', udt_name)), '[]'::json)
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name IN (${list})),
      'tables', (
        SELECT coalesce(json_agg(json_build_object('table', c.relname, 'rls', c.relrowsecurity)), '[]'::json)
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname IN (${list})))`;

  let out;
  try {
    // ponytail: the URI rides argv, which is readable via /proc on a shared host. Fine on an
    // ephemeral single-tenant runner; if this ever runs somewhere shared, split the URI into
    // PGHOST/PGUSER/PGPASSWORD env vars instead.
    out = execFileSync('psql', [url, '-At', '-c', sql], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    // psql echoes the connection string in its own errors — never let it reach a CI log.
    const detail = `${e.stderr || e.message}`.split(url).join('<redacted>');
    throw new Error(`psql failed against braird-staging:\n${detail}`);
  }
  return JSON.parse(out.trim());
}

// `information_schema` reports arrays as data_type 'ARRAY' with the element type in udt_name
// (`_text` → `text[]`); everything else is already the type name the map expects.
const pgTypeOf = (col) =>
  col.data_type === 'ARRAY' ? `${String(col.udt).replace(/^_/, '')}[]` : col.data_type;

// --- (b) DDL ----------------------------------------------------------------------
// `introspect` is injected so the comparison can be exercised against recorded payloads
// (scripts/check-native-schema.test.mjs) — the DDL leg is the half no fixture in this repo can
// prove, so it gets the unit test. The CLI always passes the real `queryStaging`.
export function checkDdl(fixture, rows, errors, notices, introspect = queryStaging) {
  const tables = Object.keys(fixture).filter((t) => VALID_BACKEND.has(rows.get(t)?.backend));
  if (!tables.length) return;

  const live = introspect(tables);
  const present = new Map(live.tables.map((t) => [t.table, t.rls]));
  const columnsByTable = new Map();
  for (const c of live.columns) {
    if (!columnsByTable.has(c.table)) columnsByTable.set(c.table, new Map());
    columnsByTable.get(c.table).set(c.column, c);
  }

  for (const table of tables) {
    const row = rows.get(table);

    if (row.backend === 'pending') {
      if (present.has(table)) {
        errors.push(
          `${MANIFEST} marks "${table}" backend:pending, but it EXISTS in braird-staging.\n` +
            `  ${row.backend_ticket} has landed — flip the row to "backend": "live" so the DDL check ` +
            `actually runs against it.`
        );
      } else {
        notices.push(
          `"${table}" skipped — backend:pending, awaiting ${row.backend_ticket}'s migration on braird-staging.`
        );
      }
      continue;
    }

    if (!present.has(table)) {
      errors.push(
        `${MANIFEST} marks "${table}" backend:live, but it is ABSENT from braird-staging.\n` +
          `  Either the migration was never applied, or the row should be "pending" with a backend_ticket.`
      );
      continue;
    }

    if (present.get(table) !== true) {
      errors.push(
        `braird-staging table "${table}" has row-level security DISABLED.\n` +
          `  Every user-scoped native table ships with RLS (SUR-1047); without it one user's rows are ` +
          `readable by another's token.`
      );
    }

    const actual = columnsByTable.get(table) ?? new Map();
    for (const [column, want] of Object.entries(fixture[table])) {
      const found = actual.get(column);
      if (!found) {
        errors.push(
          `braird-staging "${table}" is MISSING column "${column}" (fixture says ${want}).\n` +
            `  The local mirror writes it on push; the cloud would drop it silently.`
        );
        continue;
      }
      let got;
      try {
        got = logicalType(pgTypeOf(found));
      } catch (e) {
        errors.push(`braird-staging "${table}"."${column}": ${e.message}`);
        continue;
      }
      if (got !== want) {
        errors.push(
          `braird-staging "${table}"."${column}" is ${found.data_type} (logical "${got}"), but ` +
            `${FIXTURE} says "${want}".`
        );
      }
    }

    const extra = [...actual.keys()].filter(
      (c) => !(c in fixture[table]) && !SERVER_ONLY_COLUMNS.has(c)
    );
    if (extra.length) {
      notices.push(
        `"${table}" has cloud-only column(s) ${extra.join(', ')} — allowed (additive-nullable ` +
          `contract; apply_row projects unknown columns out), but if the native store should carry ` +
          `them, add them to ${FIXTURE} and native_schema().`
      );
    }
  }
}

// --- CLI --------------------------------------------------------------------------
// Guarded so the test file can import the checks without running them. `import.meta.main` is
// Node ≥24.2 only; the argv comparison works everywhere this might be run by hand.
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const [, , checkFlag] = process.argv;
  if (checkFlag !== '--check') {
    console.error(
      `usage: ${DB_URL_ENV}=postgres://... node scripts/check-native-schema.mjs --check`
    );
    process.exit(2);
  }

  const fixture = readJson(FIXTURE);
  const errors = [];
  const notices = [];

  // A thrown error is a failed CHECK, not a crash — surface it as an annotation like every other
  // finding rather than a stack trace, and never let it exit 0.
  try {
    const rows = checkManifest(fixture, errors);
    checkDdl(fixture, rows, errors, notices);
  } catch (e) {
    errors.push(e.message);
  }

  // `::notice::` (not a bare log) so a skipped pending table surfaces in the run summary — the
  // whole point of the marker is that the gap stays visible.
  for (const n of notices) console.log(`::notice::${n}`);
  if (errors.length) {
    for (const e of errors) console.error(`::error::${e}`);
    console.error(`\nnative-schema check failed with ${errors.length} issue(s) — see above.`);
    process.exit(1);
  }
  console.log(
    `native-schema: ${Object.keys(fixture).length} registered table(s), manifest complete, ` +
      `braird-staging agrees with the fixture.`
  );
}
