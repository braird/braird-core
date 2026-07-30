#!/usr/bin/env node
// Fail a release that still carries a marker deferring work UNTIL that release (SUR-1019 follow-up).
//
// The gap this closes, from the v0.14.0 cut: merging a PR onto a squash-merged base re-inserted the
// OLD paragraph after the NEW one in every file it touched, so `src/fusion.rs`, ADR 0007, and the
// CHANGELOG each simultaneously recorded a measured constant AND instructed maintainers to
// "re-derive this value ... before v0.14.0 ships". Nothing objected: `release.yml` verifies the
// CHANGELOG section *heading* and the crate version, never the prose beneath them, so a release can
// ship documentation that contradicts itself and tells the next maintainer to redo finished work.
//
// Deliberately narrow. This gates ONE class — a deferral pointing at the release being cut — not
// code hygiene. `TODO`/`FIXME` are ordinary and are not checked: a gate that fires on things people
// reasonably ship is a gate people learn to bypass.
//
// Usage:  node scripts/check-stale-release-markers.mjs [<version>]
//         node scripts/check-stale-release-markers.mjs --self-check

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Markers that always mean "not finished yet", wherever they appear.
//
// `caseSensitive` separates two different kinds of marker, and the distinction is load-bearing:
//
//   - `TUNE(` is an ANNOTATION, uppercase by convention like TODO(/FIXME(. Its case IS its syntax,
//     so it is matched case-sensitively. Matching it case-insensitively would turn an ordinary Rust
//     `fn tune(..)` or `self.tune(..)` into a hit — every `.rs` file is scanned — and fail every
//     release until the function was renamed. A word boundary does not help: it protects `attune(`
//     and `fortune(`, where a word character precedes, but an exact `tune(` is preceded by a space
//     or a `.` and matches cleanly. Blocking releases on legitimate code is how a gate earns a
//     bypass, which costs more than the miss below.
//   - The rest are PROSE, where a sentence-opening capital is ordinary writing, so they match
//     case-insensitively.
//
// Accepted miss, stated so nobody "fixes" it back: a deferral annotation written `Tune(` or `tune(`
// is not caught by the annotation marker. That is a non-conventional spelling of a convention, and
// the prose markers overlap it in practice — the real SUR-1019 text was
// "TUNE(SUR-1019 step 8a): provisional pending the device pass", which the prose marker catches on
// its own, in any casing.
const STATIC_MARKERS = [
  { pattern: 'TUNE(', why: 'a TUNE(...) deferral marker', caseSensitive: true },
  { pattern: 'provisional pending', why: 'a value still labelled provisional' },
  { pattern: 'before the release ships', why: 'work deferred to release time' },
];

/** Escape a literal so it can be embedded in a RegExp — the version's dots especially. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Compile a marker literal to a matcher. Two properties, both load-bearing:
 *
 * - **Case-insensitive unless the marker says otherwise.** A prose marker at the start of a
 *   sentence is capitalized by ordinary writing ("Before v0.15.0 ships, re-run the device pass"),
 *   which a literal lowercase `includes` walks straight past — the common case, not an edge case.
 *   Annotation markers opt out via `caseSensitive` (see [`STATIC_MARKERS`]).
 * - **Word-boundary anchored** when the literal starts with a word character, so `TUNE(` cannot hit
 *   `fortune(` or `attune(`. Note this is necessary but NOT sufficient on its own — it does nothing
 *   about an exact `tune(`, which is why case sensitivity carries that weight.
 */
const toMatcher = (pattern, caseSensitive = false) =>
  new RegExp((/^\w/.test(pattern) ? '\\b' : '') + escapeRe(pattern), caseSensitive ? '' : 'i');

/** Files that ARE the release record or ship inside it. */
function sourceFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (name.endsWith('.rs') || name.endsWith('.md')) out.push(p);
    }
  };
  walk(join(root, 'src'));
  walk(join(root, 'docs', 'adr'));
  out.push(join(root, 'CHANGELOG.md'));
  return out;
}

/** Every marker hit in `text`, as {line, why, excerpt}. `version` may be undefined. */
export function findMarkers(text, version) {
  const markers = [...STATIC_MARKERS];
  if (version) {
    // The version-specific form — "before v0.14.0 ships". A bare "ships" is useless here: it is a
    // substring of `memberships`/`relationships`, which appear 150+ times in legitimate prose.
    markers.push({
      pattern: `before v${version} ships`,
      why: `work deferred until v${version}, which is the release being cut`,
    });
  }
  // Scan a 3-line sliding window with whitespace collapsed, not line by line. Prose here wraps at
  // ~100 cols, so a marker routinely straddles a line break — the real ADR 0007 case was "before
  // the release\n   ships", which every single-line check walks straight past. Hits are deduped by
  // (line, pattern) so a marker sitting inside three overlapping windows is reported once.
  const lines = text.split('\n');
  const seen = new Set();
  const hits = [];
  const compiled = markers.map((m) => ({
    ...m,
    re: toMatcher(m.pattern, m.caseSensitive),
    firstWordRe: toMatcher(m.pattern.split(' ')[0], m.caseSensitive),
  }));
  for (let i = 0; i < lines.length; i++) {
    const window = lines.slice(i, i + 3).join(' ').replace(/\s+/g, ' ');
    for (const m of compiled) {
      if (!m.re.test(window)) continue;
      // Report the line the marker actually STARTS on, not the window's first line — a release
      // gate that points at the wrong line costs whoever is debugging it more than it saves.
      let at = i;
      for (let j = i; j < Math.min(i + 3, lines.length); j++) {
        if (m.firstWordRe.test(lines[j])) {
          at = j;
          break;
        }
      }
      // Dedupe on the resolved line, so overlapping windows report a marker exactly once.
      const key = `${m.pattern}@${at}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ line: at + 1, why: m.why, excerpt: lines[at].trim().slice(0, 120) });
    }
  }
  return hits;
}

function selfCheck() {
  // The negative leg: prove the detector actually fires, so a silently-broken guard cannot pass as
  // "no markers found". Every marker gets a case, plus one that must NOT trip.
  const cases = [
    ['/// TUNE(SUR-1019 step 8a): provisional', true],
    ['the value is provisional pending the device pass', true],
    ['re-derive this before v9.9.9 ships', true],
    // Wrapped across a line break — the real ADR 0007 shape, which a line-by-line scan misses.
    ['distributions on the device corpus before the release\n   ships (the constant sits', true],
    // Sentence-start capitalization — how prose is ORDINARILY written, and what a literal
    // lowercase `includes` walked straight past until this was fixed.
    ['Provisional pending the device pass against the real model.', true],
    ['Before v9.9.9 ships, re-run the device pass.', true],
    ['PROVISIONAL PENDING the device pass', true],
    // …without letting case-insensitivity widen the ANNOTATION marker onto ordinary Rust. Every
    // `.rs` file is scanned, so a hit here would fail every release until the function was renamed.
    // The first two are why `TUNE(` stays case-sensitive: a word boundary alone does not save them,
    // because a space or a `.` before `tune` IS a boundary.
    ['fn tune(x: f64) -> f64 { x }', false],
    ['let y = self.tune(0.5);', false],
    ['let seed = fortune(rng);', false],
    ['fn attune(&self) -> f64 { 0.0 }', false],
    // The accepted miss, pinned so it is a decision rather than a surprise: a lowercase spelling of
    // the annotation is NOT caught by the annotation marker (see STATIC_MARKERS). Real deferrals
    // carry prose alongside, which is caught in any casing — the line below that.
    ['/// Tune(SUR-1019): still outstanding', false],
    ['/// Tune(SUR-1019): provisional pending the device pass', true],
    ['`collection_memberships` converge to ONE row', false], // contains "ships"
    ['relationships between notes are row-per-edge', false], // contains "ships" too
    ['ranking policy is core-owned and version-pinned', false],
  ];
  let ok = true;
  for (const [text, shouldTrip] of cases) {
    const tripped = findMarkers(text, '9.9.9').length > 0;
    if (tripped !== shouldTrip) {
      console.error(`self-check FAILED: expected trip=${shouldTrip} for: ${text}`);
      ok = false;
    }
  }
  console.log(ok ? 'check-stale-release-markers: self-check OK' : 'self-check FAILED');
  process.exit(ok ? 0 : 1);
}

const arg = process.argv[2];
if (arg === '--self-check') selfCheck();

const version = arg && arg !== '--self-check' ? arg.replace(/^v/, '') : undefined;
const root = process.cwd();
let failed = 0;
for (const file of sourceFiles(root)) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    continue; // an optional path (CHANGELOG in a partial checkout) is not this gate's business
  }
  for (const hit of findMarkers(text, version)) {
    const rel = file.slice(root.length + 1).replace(/\\/g, '/');
    console.error(`::error file=${rel},line=${hit.line}::${hit.why} — ${hit.excerpt}`);
    failed++;
  }
}

if (failed > 0) {
  console.error(
    `\ncheck-stale-release-markers: ${failed} stale marker(s). The release would ship ` +
      `documentation telling maintainers to redo work this release already contains. ` +
      `Resolve each marker (or delete it if the work is done) and re-tag.`,
  );
  process.exit(1);
}
console.log(
  `check-stale-release-markers: OK — no deferral markers${version ? ` for v${version}` : ''}`,
);
