// Unit checks for the native-schema gate (SUR-1048). `node --test scripts/`.
//
// The Rust side of the lock is proved by tests/schema_parity.rs against real fixtures. The DDL leg
// is the half nothing in this repo can prove — it only ever runs against braird-staging — so its
// comparison logic is exercised here against recorded `information_schema` payloads. Without this,
// every branch that reports a MISSING column, a retyped column, disabled RLS, or a stale
// backend:pending row would ship never having been executed.
//
// stdlib only: node:test + node:assert, no framework, no fixtures directory.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkDdl, checkManifest } from './check-native-schema.mjs';
import { logicalType } from './logical-type.mjs';

const SCRIPT = fileURLToPath(new URL('./check-native-schema.mjs', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

// Run the CLI for real, with BRAIRD_STAGING_DB_URL scrubbed so the assertion holds in CI (where the
// secret IS set) exactly as it does locally.
const runCli = (args) =>
  spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: { ...process.env, BRAIRD_STAGING_DB_URL: '' },
  });

// --- exit-code discipline (SUR-1048 review, release-integrity-reviewer) ---
// GATING §3.1 on scripts/: "a check that can pass without running is worse than no check". These
// pin the two ways this one could silently become a no-op.

test('the CLI refuses to run without --check instead of exiting 0', () => {
  const { status, stderr } = runCli([]);
  assert.notEqual(status, 0, 'a bare invocation must not look like success');
  assert.equal(status, 2);
  assert.match(stderr, /usage:/);
});

test('the CLI exits non-zero when the DB secret is missing — it never skips silently', () => {
  const { status, stderr } = runCli(['--check']);
  assert.equal(status, 1);
  assert.match(stderr, /BRAIRD_STAGING_DB_URL is not set/);
});

const FIXTURE = {
  widgets: { id: 'text', count: 'int', updated_at: 'int', deleted: 'bool' },
};

const manifest = (backend, extra = {}) => ({
  entries: [
    {
      table: 'widgets',
      ticket: 'SUR-1',
      backend,
      backend_ticket: 'SUR-2',
      pk: ['id'],
      pk_scope: 'global',
      ...extra,
    },
  ],
});

// Build a `queryStaging`-shaped payload. `cols` is { column: pg data_type }. `key` is the cloud
// constraint's column set (default: a plain PK on the local pk).
// `cols` values may be a bare pg type string, or {type, nullable, default} for the NOT NULL cases.
const OK_POLICY = {
  table: 'widgets',
  name: 'owner',
  roles: ['authenticated'],
  cmd: 'ALL',
  qual: '(auth.uid() = user_id)',
  with_check: '(auth.uid() = user_id)',
};
const OK_TRIGGER = { table: 'widgets', name: 't02_change_seq', fn: 'stamp_change_seq' };

const staged = (
  cols,
  {
    rls = true,
    absent = false,
    key = ['id'],
    keyType = 'p',
    policies = [OK_POLICY],
    triggers = [OK_TRIGGER],
  } = {}
) => () => ({
  tables: absent ? [] : [{ table: 'widgets', rls }],
  constraints: absent || !key ? [] : [{ table: 'widgets', type: keyType, cols: key }],
  policies: absent ? [] : policies,
  triggers: absent ? [] : triggers,
  columns: absent
    ? []
    : Object.entries(cols).map(([column, spec]) => {
        const { type, nullable = 'YES', default: def = null } =
          typeof spec === 'string' ? { type: spec } : spec;
        return {
          table: 'widgets',
          column,
          data_type: type,
          udt: type,
          nullable,
          default: def,
        };
      }),
});

const CLOUD_OK = {
  id: 'text',
  count: 'bigint',
  updated_at: 'bigint',
  deleted: 'boolean',
  user_id: 'uuid',
  change_seq: 'bigint',
};

/** Run both legs and return { errors, notices }. */
function run(manifestDoc, introspect) {
  const errors = [];
  const notices = [];
  const rows = checkManifest(FIXTURE, errors, manifestDoc);
  checkDdl(FIXTURE, rows, errors, notices, introspect);
  return { errors, notices };
}

test('a live table matching braird-staging passes clean', () => {
  const { errors, notices } = run(manifest('live'), staged(CLOUD_OK));
  assert.deepEqual(errors, []);
  // user_id + change_seq are server-only by construction — they must NOT be reported as extras,
  // or every table would carry a permanent notice and the signal would be worthless.
  assert.deepEqual(notices, []);
});

test('a fixture column missing from the cloud fails', () => {
  const { count, ...withoutCount } = CLOUD_OK;
  const { errors } = run(manifest('live'), staged(withoutCount));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /MISSING column "count"/);
});

test('a retyped cloud column fails', () => {
  const { errors } = run(manifest('live'), staged({ ...CLOUD_OK, count: 'text' }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /"count" is text \(logical "text"\).*says "int"/s);
});

test('a narrow integer column fails — epoch ms overflows int4', () => {
  // The logical vocabulary calls integer and bigint both `int`, which is right for the SQLite
  // mirror and wrong as a cloud acceptance rule: updated_at is epoch MILLISECONDS (~1.8e12).
  const { errors } = run(manifest('live'), staged({ ...CLOUD_OK, count: 'integer' }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /cannot hold an epoch-millisecond value/);
});

test('RLS disabled on a live table fails', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { rls: false }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /row-level security DISABLED/);
});

test('a cloud-only column is a notice, not a failure', () => {
  const { errors, notices } = run(manifest('live'), staged({ ...CLOUD_OK, colour: 'text' }));
  assert.deepEqual(errors, []);
  assert.equal(notices.length, 1);
  assert.match(notices[0], /cloud-only column\(s\) colour/);
});

test('a live table absent from braird-staging fails', () => {
  const { errors } = run(manifest('live'), staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /ABSENT from braird-staging/);
});

test('a pending table that is absent is skipped with a notice', () => {
  const { errors, notices } = run(manifest('pending'), staged({}, { absent: true }));
  assert.deepEqual(errors, []);
  assert.match(notices[0], /skipped — backend:pending, awaiting SUR-2/);
});

test('a pending table that EXISTS fails — the marker cannot rot', () => {
  const { errors } = run(manifest('pending'), staged(CLOUD_OK));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /flip the row to "backend": "live"/);
});

test('a pending row without a backend_ticket fails', () => {
  const doc = manifest('pending');
  delete doc.entries[0].backend_ticket;
  const { errors } = run(doc, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /REQUIRES a "backend_ticket"/);
});

test('a fixture table with no manifest row fails', () => {
  const { errors } = run({ entries: [] }, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /table "widgets" has no row/);
});

// --- key constraint (SUR-1048 review, P1) ---
// A wrong key is invisible to a column-only compare but changes convergence outright.

test('a user-scoped cloud key satisfies the local pk', () => {
  // Local pk is `key`-style single-column; the cloud scopes it by user_id. Both express the same
  // uniqueness because the local mirror never stores user_id.
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { key: ['user_id', 'id'] }));
  assert.deepEqual(errors, []);
});

test('a UNIQUE constraint satisfies the key requirement, not just PRIMARY KEY', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { key: ['id'], keyType: 'u' }));
  assert.deepEqual(errors, []);
});

test('a key on the wrong column fails', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { key: ['count'] }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /no PRIMARY KEY or UNIQUE constraint on \(id, user_id\) or \(id\)/);
});

test('a broader composite key fails — it would permit duplicate logical rows', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { key: ['id', 'count'] }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /no PRIMARY KEY or UNIQUE constraint/);
});

test('no key at all fails', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { key: null }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /Found: none/);
});

test('a manifest row without a pk fails', () => {
  const doc = manifest('pending');
  delete doc.entries[0].pk;
  const { errors } = run(doc, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /REQUIRES a non-empty "pk" array/);
});

// --- per-user key scope (SUR-1048 review round 2, P1) ---
// user_settings.key repeats across users: a bare UNIQUE(key) lets the first user to write
// "prompt_cadence" occupy it globally, and the next user's upsert conflicts with a row RLS hides.

test('a per_user table REJECTS a bare key on the local pk', () => {
  const { errors } = run(
    manifest('live', { pk_scope: 'per_user' }),
    staged(CLOUD_OK, { key: ['id'] })
  );
  assert.equal(errors.length, 1);
  assert.match(errors[0], /pk_scope:per_user.*MUST include user_id/s);
});

test('a per_user table accepts the user-scoped key', () => {
  const { errors } = run(
    manifest('live', { pk_scope: 'per_user' }),
    staged(CLOUD_OK, { key: ['user_id', 'id'] })
  );
  assert.deepEqual(errors, []);
});

test('a manifest row without pk_scope fails', () => {
  const doc = manifest('pending');
  delete doc.entries[0].pk_scope;
  const { errors } = run(doc, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /REQUIRES "pk_scope" of global\|per_user/);
});

// --- required server-side columns (SUR-1048 review round 2, P1) ---
// Absent from the fixture by design, but the cloud table cannot function without them.

test('a live table missing user_id fails', () => {
  const { user_id, ...noUserId } = CLOUD_OK;
  const { errors } = run(manifest('live'), staged(noUserId));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /MISSING the server-side column "user_id"/);
});

test('a live table missing change_seq fails', () => {
  const { change_seq, ...noSeq } = CLOUD_OK;
  const { errors } = run(manifest('live'), staged(noSeq));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /MISSING the server-side column "change_seq"/);
});

test('a mistyped change_seq fails', () => {
  const { errors } = run(manifest('live'), staged({ ...CLOUD_OK, change_seq: 'text' }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /"change_seq" is text .*needs "int"/s);
});

// --- RLS policies, not just the flag (SUR-1048 review round 3, P1) ---
// get_page sends no user_id filter, so RLS IS the tenant boundary. relrowsecurity=true with no
// policy is deny-all; with USING (true) it is a cross-tenant leak. Both leave the flag true.

test('RLS enabled with NO policies fails — that is deny-all', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { policies: [] }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /RLS ENABLED but NO policies/);
});

test('a USING (true) policy for authenticated fails — cross-tenant exposure', () => {
  const leaky = { ...OK_POLICY, qual: 'true', with_check: 'true' };
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { policies: [leaky] }));
  assert.ok(errors.length >= 1);
  assert.match(errors.join('\n'), /grants every user access to every other user's rows/);
});

test('policies that never consult auth.uid() fail', () => {
  const notScoped = { ...OK_POLICY, qual: '(status = \'live\')', with_check: null };
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { policies: [notScoped] }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /none reference auth\.uid\(\)/);
});

// --- change_seq must be stamped, not merely present (round 3, P1) ---

test('a change_seq column without its stamping trigger fails', () => {
  const { errors } = run(manifest('live'), staged(CLOUD_OK, { triggers: [] }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /no change_seq stamping trigger/);
});

// --- unfillable mandatory cloud columns (round 3, P1) ---

test('a NOT NULL cloud-only column with no default fails', () => {
  const { errors } = run(
    manifest('live'),
    staged(
      { ...CLOUD_OK, tenant: { type: 'text', nullable: 'NO' } },
      { triggers: [] } // no trigger that could populate it
    )
  );
  // The missing trigger also trips the change_seq check; assert ours is present.
  assert.match(errors.join('\n'), /NOT NULL cloud-only column\(s\) tenant/);
});

// (the nullable-extra-column case is covered by "a cloud-only column is a notice, not a failure")

// --- the shared logical-type map (SUR-1048 review, regression-reviewer) ---
// logical-type.mjs is imported by BOTH gates, so its contract is tested directly rather than only
// through this script's callers — the timestamp rejection changed extract-sync-schema.mjs's
// behaviour too (it used to map timestamps to `int`), and that change needs its own pin.

test('logicalType rejects every timestamp/date/time form, for both callers', () => {
  for (const t of ['timestamp', 'timestamp with time zone', 'timestamptz', 'date', 'time']) {
    assert.throws(() => logicalType(t), /unusable pg type/, `${t} should be rejected`);
  }
});

test('logicalType still maps the types the synced fixture actually uses', () => {
  assert.equal(logicalType('bigint'), 'int');
  assert.equal(logicalType('text'), 'text');
  assert.equal(logicalType('uuid'), 'text');
  assert.equal(logicalType('boolean'), 'bool');
  assert.equal(logicalType('double precision'), 'real');
  assert.equal(logicalType('jsonb'), 'json');
  assert.equal(logicalType('text[]'), 'json');
});

// --- timestamp columns (SUR-1048 review, P2) ---

test('a timestamptz column fails instead of passing as an epoch int', () => {
  // PostgREST sends these as ISO strings; store.rs's ColType::Int is as_i64(), so they would land
  // as NULL on every sync. Equating them with `int` would have shipped that green.
  const { errors } = run(
    manifest('live'),
    staged({ ...CLOUD_OK, updated_at: 'timestamp with time zone' })
  );
  assert.equal(errors.length, 1);
  assert.match(errors[0], /unusable pg type .*Use bigint/s);
});

test('a manifest row for an unknown table fails', () => {
  const doc = manifest('pending');
  doc.entries.push({
    table: 'ghosts',
    ticket: 'SUR-3',
    backend: 'pending',
    backend_ticket: 'SUR-4',
    pk: ['id'],
    pk_scope: 'global',
  });
  const { errors } = run(doc, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /"ghosts" is not a table in/);
});
