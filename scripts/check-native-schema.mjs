#!/usr/bin/env node
// check-native-schema — prove the native-first schema lock against the DDL actually applied to
// braird-staging (SUR-1048).
//
// `vendored/schema/sync-schema.json` is DERIVED from surfc, so `schema-drift.yml` can re-derive it
// and catch drift by construction. The native-first tables (SUR-996: questions,
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
//   Use a DEDICATED READ-ONLY role — this gate only reads catalogs, so a migration/service
//   credential in CI would be over-privileged for the job (raised by security-reviewer):
//
//     CREATE ROLE schema_checker LOGIN PASSWORD '…';
//     GRANT USAGE ON SCHEMA public TO schema_checker;
//     GRANT SELECT ON ALL TABLES IN SCHEMA public TO schema_checker;
//     ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO schema_checker;
//
//   That last line is not optional: the tables this registry is FOR do not exist yet, so without
//   default privileges they land outside the grant and every column reads as missing.
//   The role must be able to SEE the registered tables — `information_schema.columns` is
//   privilege-filtered, while the `pg_class` half is not. An under-privileged role therefore
//   reports a live table's columns as all-missing (a loud failure, but a confusing one). Note the
//   present/absent verdict itself comes from `pg_class` and stays correct regardless of grants.
//
//   Connection string: use Supabase's SESSION POOLER host, not the direct `db.<ref>.supabase.co`
//   one — direct connections are IPv6-only on post-2024 projects and GitHub runners are IPv4-only.
//   The pooler encodes the project ref in the username (`<role>.<project-ref>`).

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { logicalType } from './logical-type.mjs';

const FIXTURE = 'vendored/schema/native-schema.json';
const MANIFEST = 'vendored/schema/native-manifest.json';
const DB_URL_ENV = 'BRAIRD_STAGING_DB_URL';

const VALID_BACKEND = new Set(['live', 'pending']);
const VALID_PK_SCOPE = new Set(['global', 'per_user']);
const TICKET_RE = /^SUR-\d+$/;
// A table identifier we are willing to interpolate into SQL. The names come from our own
// checked-in fixture, but a gate that builds SQL from a file should still refuse anything that
// isn't a plain identifier.
const IDENT_RE = /^[a-z_][a-z0-9_]*$/;

// Columns the cloud MUST have that the local mirror deliberately never stores. Not merely tolerated
// — required, and type-checked (raised on SUR-1048 review): `push::upsert_group` injects `user_id`
// into every row unconditionally, and `PostgrestClient::get_page` filters and orders every pull on
// `change_seq`. A migration that omits either reports green on a fixture-only compare and then fails
// at runtime on the first push or pull. Absent from the fixture because the local store never holds
// them, which is exactly why they need naming here.
// The PHYSICAL type is pinned, not just the logical one. `change_seq` is the watermark every pull
// compares against and the trigger increments forever, so a narrow int would eventually overflow
// and stop writes dead; `user_id` holds `auth.uid()`, which is a uuid. Neither column is in the
// fixture (the local store holds neither), so the fixture-driven type checks never see them —
// which is exactly why they are spelled out here (raised on review after the first hardening pass).
// Each spec carries its own aliases and its own explanation, so the loop below stays generic — a
// future server column adds a row here and needs no new branch in the check (raised on review:
// the int8 alias and the per-column error text were both name-switches in the loop body).
const SERVER_REQUIRED_COLUMNS = {
  user_id: {
    logical: 'text',
    physical: 'uuid',
    why: 'user_id holds auth.uid(), which is a uuid.',
  },
  change_seq: {
    logical: 'int',
    physical: 'bigint',
    aliases: new Set(['int8']),
    why:
      'change_seq is a monotonically increasing watermark stamped on every write; a narrower type ' +
      'overflows and then rejects every subsequent write.',
  },
};

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
    // `pk` is locked against TableSchema.pk by tests/schema_parity.rs; here we only need it to be
    // present and well-formed, since the DDL leg compares it to the cloud's key constraint.
    if (!Array.isArray(row.pk) || !row.pk.length || !row.pk.every((c) => typeof c === 'string')) {
      errors.push(
        `${where}: REQUIRES a non-empty "pk" array of column names — the key is what decides ` +
          `convergence (deterministic-pk OR-set vs duplicate rows), so it cannot go unstated.`
      );
    }
    if (!VALID_PK_SCOPE.has(row.pk_scope)) {
      errors.push(
        `${where}: REQUIRES "pk_scope" of global|per_user — whether the local pk is unique across ` +
          `all users (a uuid) or only within one (a settings key). Guessing it wrong either blocks ` +
          `users from each other or permits duplicate rows, and it is not derivable from the shape.`
      );
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

  // One round trip: column shapes (with nullability + default), the rowsecurity flag, the actual
  // RLS policies, and the non-internal triggers — as one JSON document.
  const sql = `
    SELECT json_build_object(
      'columns', (
        SELECT coalesce(json_agg(json_build_object(
          'table', table_name, 'column', column_name, 'data_type', data_type, 'udt', udt_name,
          'nullable', is_nullable, 'default', column_default,
          'identity', is_identity, 'generated', is_generated)), '[]'::json)
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name IN (${list})),
      'policies', (
        SELECT coalesce(json_agg(json_build_object(
          'table', tablename, 'name', policyname, 'roles', roles, 'cmd', cmd,
          'qual', qual, 'with_check', with_check)), '[]'::json)
        FROM pg_policies WHERE schemaname = 'public' AND tablename IN (${list})),
      'triggers', (
        SELECT coalesce(json_agg(json_build_object(
          'table', t.relname, 'name', tg.tgname, 'fn', p.proname,
          'enabled', tg.tgenabled, 'type', tg.tgtype)), '[]'::json)
        FROM pg_trigger tg
        JOIN pg_class t ON t.oid = tg.tgrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_proc p ON p.oid = tg.tgfoid
        WHERE NOT tg.tgisinternal AND n.nspname = 'public' AND t.relname IN (${list})),
      'tables', (
        SELECT coalesce(json_agg(json_build_object('table', c.relname, 'rls', c.relrowsecurity)), '[]'::json)
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname IN (${list})),
      'constraints', (
        SELECT coalesce(json_agg(j), '[]'::json) FROM (
          SELECT json_build_object(
            'table', t.relname,
            'type', con.contype,
            'cols', (SELECT array_agg(a.attname ORDER BY a.attname)
                     FROM unnest(con.conkey) AS k(attnum)
                     JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum)) AS j
          FROM pg_constraint con
          JOIN pg_class t ON t.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE n.nspname = 'public' AND con.contype IN ('p', 'u') AND t.relname IN (${list})
        ) sub))`;

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

// The cloud key must enforce the SAME uniqueness the local pk does, and `pk_scope` says what that
// is. The distinction is load-bearing (raised on SUR-1048 review):
//
//   global   — the local pk is unique across ALL users on its own (a uuid, or an id derived from
//              uuids). `(pk)` and `(pk, user_id)` both express that, so either is accepted.
//   per_user — the local pk is only unique WITHIN a user. `user_settings.key` is the case: every
//              user has a row keyed "prompt_cadence". A bare UNIQUE (key) would let the first user
//              to write it occupy that key globally, and the next user's upsert would conflict with
//              a row RLS hides from them — a bug that only appears with two accounts. Only
//              `(pk, user_id)` is accepted.
//
// A key broader than required is equally wrong in either mode: it permits duplicate logical rows,
// breaking the deterministic-pk OR-set that makes two devices converge on one. PRIMARY KEY and
// UNIQUE both satisfy the check — PostgREST upserts resolve on either.
function checkKey(table, row, constraints, errors) {
  if (!Array.isArray(row.pk) || !row.pk.length) return; // already reported by checkManifest
  const scoped = [...row.pk, 'user_id'].sort().join(',');
  const bare = [...row.pk].sort().join(',');
  const perUser = row.pk_scope === 'per_user';
  const acceptable = perUser ? [scoped] : [scoped, bare];

  const found = constraints
    .filter((c) => c.table === table)
    .map((c) => [...(c.cols ?? [])].sort().join(','));

  if (!found.some((cols) => acceptable.includes(cols))) {
    const wanted = acceptable
      .map((c) => `(${c.split(',').join(', ')})`)
      .join(' or ');
    errors.push(
      `braird-staging "${table}" has no PRIMARY KEY or UNIQUE constraint on ${wanted}.\n` +
        `  Found: ${found.length ? found.map((c) => `(${c.split(',').join(', ')})`).join(' ') : 'none'}.\n` +
        (perUser
          ? `  This table is pk_scope:per_user — "${row.pk.join(', ')}" repeats across users, so the ` +
            `constraint MUST include user_id or one user's row blocks every other user's.`
          : `  The key decides convergence — a broader key lets two devices create duplicate logical ` +
            `rows instead of converging on one, and PostgREST upserts need it to resolve.`)
    );
  }
}

// RLS. `relrowsecurity = true` is necessary and nowhere near sufficient (raised on review):
// enabling RLS with NO policy is deny-all, which makes native sync silently unusable, and a
// `USING (true)` policy leaves the flag true while exposing every user's rows. This matters more
// here than for a typical table because `PostgrestClient::get_page` does NOT filter by user_id —
// the pull URL is `?change_seq=gt.N&order=...`, so RLS *is* the tenant boundary, not a backstop.
const EXPOSED_ROLES = new Set(['public', 'authenticated', 'anon']);
// The roles a native client can actually arrive as. `service_role`/`postgres` bypass RLS entirely,
// so a policy scoped to them proves nothing about what a real caller can do.
const CLIENT_ROLES = new Set(['public', 'authenticated']);
const WRITE_COMMANDS = new Set(['ALL', 'INSERT', 'UPDATE']);

function checkRls(table, policies, errors) {
  const mine = policies.filter((p) => p.table === table);
  if (!mine.length) {
    errors.push(
      `braird-staging "${table}" has RLS ENABLED but NO policies — that is deny-all.\n` +
        `  Every native sync read returns zero rows and every write is rejected, with no error that ` +
        `names RLS as the cause.`
    );
    return;
  }
  for (const p of mine) {
    const roles = (p.roles ?? []).map((r) => String(r).toLowerCase());
    const exposed = roles.some((r) => EXPOSED_ROLES.has(r));

    // Read side: a bare `true` USING hands every row to every caller.
    if (p.qual != null && String(p.qual).trim().toLowerCase() === 'true' && exposed) {
      errors.push(
        `braird-staging "${table}" policy "${p.name}" is USING (true) for role(s) ` +
          `${roles.join(', ')} — that grants every user read access to every other user's rows.`
      );
    }

    // Write side, checked SEPARATELY (migration-reviewer, SUR-1048). A scoped USING with a
    // permissive WITH CHECK is the write-escape: reads are correctly fenced, but a user can INSERT
    // or UPDATE rows carrying someone else's user_id. Testing the two predicates together — or
    // only for a literal `true` — misses it, since the scoped read predicate satisfies the search
    // and a permissive check need not be spelled `true`.
    //
    // Postgres: when WITH CHECK is omitted on UPDATE/ALL, USING governs writes too, so the
    // effective write predicate is `with_check ?? qual`. INSERT policies have no USING at all.
    if (WRITE_COMMANDS.has(String(p.cmd ?? '').toUpperCase())) {
      const effective = p.with_check ?? p.qual;
      if (effective == null || !String(effective).includes('auth.uid()')) {
        errors.push(
          `braird-staging "${table}" policy "${p.name}" governs writes (${p.cmd}) but its ` +
            `effective WITH CHECK predicate does not reference auth.uid()` +
            (p.with_check == null ? ' (none set, and USING does not either)' : `: ${p.with_check}`) +
            `.\n  A user could INSERT or UPDATE rows owned by another user even though reads are ` +
            `scoped — the write side needs its own predicate.`
        );
      }
    }
  }
  // COVERAGE per operation. "At least one scoped policy exists" is not enough: RLS denies any
  // command no policy covers, so a table with only a user-scoped SELECT policy reads correctly and
  // rejects every push — green gate, broken sync (raised on review). Sync needs SELECT (pull),
  // INSERT and UPDATE (upsert); it never hard-deletes, since `deleted` is a soft-delete column.
  for (const cmd of ['SELECT', 'INSERT', 'UPDATE']) {
    // Only policies granted to a role the CLIENT actually uses count. Native sync reaches
    // PostgREST as `authenticated`; a policy granted solely to `service_role` or `postgres` covers
    // a path no client takes, and those roles bypass RLS anyway — so counting it would report
    // coverage for a command RLS still denies to every real caller (raised on review).
    //
    // DIRECT grants only, deliberately. Postgres would also apply a policy granted to a GROUP role
    // that `authenticated` inherits, and this rejects that (raised on review as a false-positive
    // risk). Resolving membership means recursing pg_auth_members at introspection time to answer
    // "could this role ever apply" — more machinery, and a weaker contract, than simply requiring
    // the policy to name the client role. Supabase's own convention is `TO authenticated`, which is
    // what migration 0055 does. So this is a stated schema constraint, not an oversight; the error
    // below says so, and the failure is loud rather than silent.
    // Two stages, so the question being asked is explicit: first "does any policy cover this
    // command at all", then "does any of those serve a client role".
    const forCmd = mine.filter((p) => {
      const c = String(p.cmd ?? '').toUpperCase();
      return c === cmd || c === 'ALL';
    });
    const covering = forCmd.filter((p) =>
      (p.roles ?? []).some((r) => CLIENT_ROLES.has(String(r).toLowerCase()))
    );
    if (!covering.length) {
      const backendOnly = forCmd;
      errors.push(
        `braird-staging "${table}" has no RLS policy covering ${cmd} for a client role — RLS denies ` +
          `any command no policy grants, so this ${cmd === 'SELECT' ? 'makes every pull return nothing' : 'rejects every push'}.` +
          (backendOnly.length
            ? `\n  There ${backendOnly.length === 1 ? 'is a policy' : 'are policies'} for ${cmd}, but ` +
              `granted only to ${[...new Set(backendOnly.flatMap((p) => p.roles ?? []))].join(', ')} — ` +
              `those bypass RLS and are not the role PostgREST uses.\n` +
              `  Note this check requires a DIRECT grant to ${[...CLIENT_ROLES].join('/')}: a policy on a ` +
              `group role that authenticated merely inherits would work in Postgres but is rejected ` +
              `here on purpose, so the grantee is legible from the migration alone.`
            : '')
      );
      continue;
    }
    // The read side needs its own scoping assertion; the write side is checked above.
    if (cmd === 'SELECT' && !covering.some((p) => String(p.qual ?? '').includes('auth.uid()'))) {
      errors.push(
        `braird-staging "${table}" has a SELECT policy, but its USING predicate does not reference ` +
          `auth.uid() — nothing ties a readable row to its owner, and get_page sends no user_id filter.`
      );
    }
  }
}

// `change_seq` must be STAMPED SERVER-SIDE on every write, not merely present. `upsert_group` never
// sends it, so: a bare NOT NULL column rejects every insert, and a nullable one leaves the value
// NULL — which `change_seq=gt.<cursor>` excludes, making the row permanently invisible to pull.
// surfc does this with the migration-0051 trigger; the column without the trigger is a trap.
// The logical vocabulary collapses every integer width to `int`, which is right for comparing a
// SQLite mirror (INTEGER is 64-bit) but wrong as an acceptance rule for the CLOUD column: braird
// stamps `updated_at` and friends in epoch MILLISECONDS (~1.8e12, see src/sync/mod.rs), and pg
// `integer` tops out at 2.1e9. A migration declaring `integer` would pass a logical-type compare
// and then fail every upsert with a numeric-range error. Native tables use bigint for every integer
// column — there is no reason for a narrower one, so this needs no per-column allowlist.
function checkPhysicalType(table, column, want, found, errors) {
  const t = String(found.data_type).toLowerCase();
  if (want === 'int' && (t === 'integer' || t === 'smallint')) {
    errors.push(
      `braird-staging "${table}"."${column}" is ${found.data_type}, which cannot hold an ` +
        `epoch-millisecond value (~1.8e12 today; ${t} caps at ${t === 'smallint' ? '32767' : '2.1e9'}).\n` +
        `  Native tables use bigint for every integer column — the first upsert would fail with a ` +
        `numeric range error despite a green logical-type compare.`
    );
  }
  // `uuid` normalises to logical `text`, which is right for the SQLite mirror (no uuid type) and
  // wrong as a cloud acceptance rule: it is a CONSTRAINT the client cannot honour. Native ids are
  // not all uuids — `question_note_overrides.id` is the colon-joined `question_id:note_id`, and
  // `user_settings.key` is a setting name. PostgREST rejects a non-uuid value on every upsert while
  // the schema gate stays green (raised on review).
  if (want === 'text' && t === 'uuid') {
    errors.push(
      `braird-staging "${table}"."${column}" is uuid, but the native store treats it as opaque ` +
        `text.\n  Core does not guarantee uuid-shaped values here (deterministic ids and settings ` +
        `keys are not uuids), so every upsert carrying one would be rejected. Use text.`
    );
  }
}

// pg_trigger.tgtype bitmask. A name match alone accepts a DISABLED trigger, an AFTER trigger (too
// late to set NEW.change_seq), or a DELETE-only one — none of which stamp an insert (raised on
// review). tgenabled 'D' is disabled; 'O'/'A'/'R' all fire on origin writes.
const TG_ROW = 1;
const TG_BEFORE = 2;
const TG_INSERT = 4;
const TG_UPDATE = 16;

function checkChangeSeqTrigger(table, triggers, errors) {
  const named = triggers.filter((t) => t.table === table && /change_seq/i.test(`${t.name} ${t.fn}`));

  const stamps = named.filter((t) => {
    const type = Number(t.type ?? 0);
    return (
      String(t.enabled ?? 'O').toUpperCase() !== 'D' &&
      (type & TG_BEFORE) !== 0 &&
      (type & TG_ROW) !== 0 &&
      (type & TG_INSERT) !== 0 &&
      (type & TG_UPDATE) !== 0
    );
  });

  if (named.length && !stamps.length) {
    const t = named[0];
    const type = Number(t.type ?? 0);
    const why = [
      String(t.enabled ?? 'O').toUpperCase() === 'D' && 'it is DISABLED',
      (type & TG_BEFORE) === 0 && 'it is AFTER, too late to set NEW.change_seq',
      (type & TG_ROW) === 0 && 'it is a STATEMENT trigger, so it sees no row',
      (type & TG_INSERT) === 0 && 'it does not fire on INSERT',
      (type & TG_UPDATE) === 0 && 'it does not fire on UPDATE, so edited rows keep a stale watermark',
    ].filter(Boolean);
    errors.push(
      `braird-staging "${table}" has a change_seq trigger ("${t.name}") that cannot stamp writes: ` +
        `${why.join('; ')}.\n  It must be BEFORE INSERT OR UPDATE FOR EACH ROW and enabled, or ` +
        `pushed rows carry no watermark and never come back on a pull.`
    );
    return;
  }

  if (!stamps.length) {
    errors.push(
      `braird-staging "${table}" has no change_seq stamping trigger.\n` +
        `  The column alone is not enough: pushes never supply change_seq, so without the ` +
        `server-side trigger (surfc migration 0051, t02_change_seq) rows are either rejected ` +
        `(NOT NULL) or invisible to every pull (NULL fails change_seq > cursor).`
    );
  }
}

// --- (b) DDL ----------------------------------------------------------------------
// `introspect` is injected so the comparison can be exercised against recorded payloads
// (scripts/check-native-schema.test.mjs) — the DDL leg is the half no fixture in this repo can
// prove, so it gets the unit test. The CLI always passes the real `queryStaging`.
export function checkDdl(fixture, rows, errors, notices, introspect = queryStaging) {
  const tables = Object.keys(fixture).filter((t) => VALID_BACKEND.has(rows.get(t)?.backend));
  if (!tables.length) return;

  const live = introspect(tables);
  const present = new Map(live.tables.map((t) => [t.table, t.rls]));
  const policies = live.policies ?? [];
  const triggers = live.triggers ?? [];
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
    } else {
      checkRls(table, policies, errors);
    }
    checkChangeSeqTrigger(table, triggers, errors);

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
        continue;
      }
      checkPhysicalType(table, column, want, found, errors);
    }

    checkKey(table, row, live.constraints ?? [], errors);

    for (const [column, spec] of Object.entries(SERVER_REQUIRED_COLUMNS)) {
      const want = spec.logical;
      const found = actual.get(column);
      if (!found) {
        errors.push(
          `braird-staging "${table}" is MISSING the server-side column "${column}".\n` +
            `  It is absent from the fixture by design (the local store never holds it), but the ` +
            `cloud table cannot work without it: push injects user_id into every row, and every ` +
            `pull filters and orders on change_seq.`
        );
        continue;
      }
      // Physical type, not just logical: these columns never pass through the fixture-driven
      // checks, so `integer`/`smallint` for change_seq (which overflows the forever-incrementing
      // watermark) or a non-uuid user_id would otherwise be accepted.
      const physical = String(found.data_type).toLowerCase();
      if (physical !== spec.physical && !spec.aliases?.has(physical)) {
        errors.push(
          `braird-staging "${table}"."${column}" is ${found.data_type}, but the sync engine ` +
            `requires ${spec.physical}.\n  ${spec.why}`
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
          `braird-staging "${table}"."${column}" is ${found.data_type} (logical "${got}"), but the ` +
            `sync engine needs "${want}".`
        );
      }
    }

    const extra = [...actual.keys()].filter(
      (c) => !(c in fixture[table]) && !(c in SERVER_REQUIRED_COLUMNS)
    );

    // A cloud-only column is only harmless if the server can fill it. A push sends the fixture
    // columns plus user_id and nothing else, so a NOT NULL extra with no default and no trigger to
    // populate it rejects EVERY insert for that table (raised on review — this branch used to emit
    // a notice and stay green).
    // The trigger escape hatch this used to carry was self-defeating: it accepted ANY trigger on
    // the table as evidence the column gets populated, and every valid table has the change_seq
    // trigger — so the check could never fire (raised on review). Proving a specific trigger
    // assigns a specific column needs execution, not catalogue introspection (SUR-1049). Until
    // then this is strict: if a cloud-only column is NOT NULL with no default, a push cannot
    // satisfy it, and the four ways out are named in the message.
    const unfillable = extra.filter((c) => {
      const col = actual.get(c);
      if (col.nullable !== 'NO' || col.default != null) return false;
      // An IDENTITY or GENERATED column reports is_nullable='NO' with a NULL column_default, but
      // Postgres fills it when the insert omits it — so it is fillable despite looking otherwise
      // (raised on review; this is a false-POSITIVE guard, the opposite of the gaps above).
      return !(String(col.identity).toUpperCase() === 'YES' || String(col.generated).toUpperCase() === 'ALWAYS');
    });
    if (unfillable.length) {
      errors.push(
        `braird-staging "${table}" has NOT NULL cloud-only column(s) ${unfillable.join(', ')} with ` +
          `no default.\n` +
          `  A push sends only the fixture columns plus user_id, so every insert for this table ` +
          `would be rejected. Give the column a default, make it nullable, populate it from a ` +
          `trigger, or add it to ${FIXTURE} and native_schema() so clients supply it.`
      );
    }

    const benign = extra.filter((c) => !unfillable.includes(c));
    if (benign.length) {
      notices.push(
        `"${table}" has cloud-only column(s) ${benign.join(', ')} — allowed (additive-nullable ` +
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
