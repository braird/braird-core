// The ONE pg-type → logical-type normalization map, shared by every schema gate.
//
// Founder ruling (SUR-723 Gate-1): "compare (name, logical-type) tuples, not physical reps" —
// jsonb and text[] both collapse to `json` (stored as TEXT-JSON in SQLite ≡ cloud jsonb/text[]),
// every integer width collapses to `int`, boolean → bool. `src/store.rs`'s `ColType::logical()`
// is the Rust half of the same vocabulary.
//
// It lives in its own module because TWO gates now consume it — `extract-sync-schema.mjs`
// (re-derives the surfc fixture) and `check-native-schema.mjs` (SUR-1048, reads braird-staging's
// information_schema). Two copies of a normalization map silently disagreeing is precisely the
// drift class these gates exist to catch, so there is exactly one copy.

export function logicalType(pgType) {
  const t = pgType.toLowerCase().replace(/\s+/g, ' ').trim();
  if (t === 'text' || t === 'uuid') return 'text';
  if (t === 'bigint' || t === 'int8' || t === 'integer' || t === 'int' || t === 'int4' || t === 'smallint' || t === 'int2')
    return 'int';
  if (t === 'boolean' || t === 'bool') return 'bool';
  if (t === 'real' || t === 'double precision' || t === 'float4' || t === 'float8') return 'real';
  if (t === 'jsonb' || t === 'json' || t.endsWith('[]')) return 'json';
  // A timestamp column is ALWAYS wrong here, never "an int in disguise". Braird's wire format is
  // epoch bigint; PostgREST serialises timestamp/timestamptz as an ISO *string*, and store.rs's
  // `ColType::Int` path is `val.as_i64()` — a string yields None, so the value would land in SQLite
  // as NULL, silently, on every sync. Mapping it to `int` here would let that ship green (caught on
  // SUR-1048 review). Reject it as physically incompatible instead.
  if (t.startsWith('timestamp') || t.startsWith('date') || t.startsWith('time'))
    throw new Error(
      `unusable pg type "${pgType}": braird stores epoch bigint; PostgREST sends timestamps as ` +
        `ISO strings, which store.rs coerces to NULL. Use bigint.`
    );
  throw new Error(`unmapped pg type: "${pgType}"`);
}
