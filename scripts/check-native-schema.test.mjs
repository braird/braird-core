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
import { checkDdl, checkManifest } from './check-native-schema.mjs';

const FIXTURE = {
  widgets: { id: 'text', count: 'int', updated_at: 'int', deleted: 'bool' },
};

const manifest = (backend, extra = {}) => ({
  entries: [{ table: 'widgets', ticket: 'SUR-1', backend, backend_ticket: 'SUR-2', ...extra }],
});

// Build a `queryStaging`-shaped payload. `cols` is { column: pg data_type }.
const staged = (cols, { rls = true, absent = false } = {}) => () => ({
  tables: absent ? [] : [{ table: 'widgets', rls }],
  columns: absent
    ? []
    : Object.entries(cols).map(([column, data_type]) => ({
        table: 'widgets',
        column,
        data_type,
        udt: data_type,
      })),
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

test('logical equivalence does not fail — bigint and integer are both `int`', () => {
  const { errors } = run(manifest('live'), staged({ ...CLOUD_OK, count: 'integer' }));
  assert.deepEqual(errors, []);
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

test('a manifest row for an unknown table fails', () => {
  const doc = manifest('pending');
  doc.entries.push({ table: 'ghosts', ticket: 'SUR-3', backend: 'pending', backend_ticket: 'SUR-4' });
  const { errors } = run(doc, staged({}, { absent: true }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /"ghosts" is not a table in/);
});
