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

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
  { pattern: 'before the release ships', why: 'work deferred to release time', needsCue: true },
];

/**
 * Language that makes a temporal phrase an INSTRUCTION rather than a description.
 *
 * "before the release ships" is not evidence of anything on its own: *"CI verifies the checksums
 * before the release ships"* describes finished behaviour, and *"the migration is complete before
 * v0.15.0 ships"* is ordinary release documentation. Firing on those would fail every subsequent
 * release over correct prose — the precise way a gate earns a permanent bypass. So markers flagged
 * `needsCue` require one of these nearby.
 *
 * Checked against the real incident before being trusted: the stale ADR/CHANGELOG text was "the
 * release gate **re-derives** this value … before v0.14.0 ships", which carries a cue, and the other
 * two markers there (`TUNE(`, `provisional pending`) are unambiguous and need no cue at all. So the
 * requirement costs nothing on the case this gate was built for — verified by replaying commit
 * 212ac21, not by assertion.
 */
const DEFERRAL_CUE =
  /\b(must|should|needs? to|re-?deriv\w*|re-?run|re-?tune|re-?measure|remember to|don'?t forget|outstanding|unfinished|not yet|pending|provisional|deferred|to ?do|tune)\b/i;

/**
 * Escape hatch for the residual: a line carrying this token, or the line directly above it, is
 * exempt — the `eslint-disable-next-line` contract. Needed because the cue heuristic cannot be
 * perfect and a release must never be blocked by prose no one can legally rewrite (a quoted spec, a
 * historical note in a live document). An exemption is visible in review, which a silent miss is not.
 */
const ALLOW_TOKEN = 'stale-marker-allow';

/** Escape a literal so it can be embedded in a RegExp — the version's dots especially. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Strip a line's leading comment / quote / list decoration, replacing it with a space.
 *
 * Without this, ANY wrapped marker inside a Rust doc comment escapes: joining
 * `/// … before the release` + `/// ships …` yields "before the release /// ships", which matches
 * nothing. Doc comments wrap at ~100 cols throughout this crate, so that was the likeliest real
 * evasion of the lot. Same for Markdown blockquotes, headings, bullets, and block-comment `*`
 * continuations.
 *
 * Ordered-list prefixes (`1.`) are deliberately NOT stripped: a line opening with `0.15.0` would
 * lose its `0.` and stop matching the version marker — trading one evasion for another.
 */
const stripLinePrefix = (line) => line.replace(/^\s*(\/\/\/|\/\/!|\/\/|\/\*+|\*+\/|\*|#+|>+|[-+])\s*/, ' ');

/**
 * Reduce Markdown inline syntax to the text a reader actually sees.
 *
 * Deleting emphasis characters is not enough, because the interesting decoration is *structural*.
 * A version inside a link — `before [v0.15.0](https://…) ships` — keeps the phrase visually intact
 * while putting brackets and a whole URL between the version and `ships`. Surveying the scanned
 * files, this repo's own conventions include **19 reference links, 3 inline links, 104 table rows
 * and 2 HTML entities**, so these are house style rather than hypotheticals.
 *
 * Order is load-bearing: link *labels* must be extracted before leftover brackets become spaces,
 * or `[v0.15.0](url)` degrades to `v0.15.0 url` instead of `v0.15.0`.
 *
 * Parentheses are deliberately NOT touched — the annotation marker `TUNE(` needs its `(`, so the
 * version matcher tolerates wrapping parens itself rather than having them stripped here.
 *
 * ACCEPTED MISS: backslash-escaped punctuation inside a marker (`before \[v0.15.0\] ships`) is not
 * unescaped, so that one shape evades. There are zero backslash-escaped delimiters in any scanned
 * file, and the rule for it could not be pinned by a corpus case — an unpinnable rule is an
 * unverified claim, which by this checker's own standard is worse than a documented gap. Unescaped
 * brackets, the form anyone actually writes, ARE handled.
 */
const normalizeInline = (s) =>
  s
    .replace(/<!--[\s\S]*?-->/g, ' ') // HTML comments
    .replace(/\[\^[^\]]*\]/g, ' ') // footnote refs, before the link rules claim the brackets
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1') // images + inline links -> visible label
    .replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1') // reference links -> visible label
    // No separate autolink rule: `<https://…>` is already consumed by the inline-HTML rule below,
    // since `h` satisfies its `[a-zA-Z]`. Mutation-tested as redundant rather than assumed.
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ') // inline HTML (<sub>, <b>, <code>…) and autolinks
    .replace(/&[a-zA-Z]+;|&#\d+;/g, ' ') // entities, incl. &nbsp;
    .replace(/[|[\]]/g, ' ') // table pipes + any leftover brackets
    .replace(/[`*_~]/g, ''); // emphasis / code / strikethrough delimiters

// Emphasis stripping only ever DELETES (never inserts a space), so it cannot forge a phrase out of
// an identifier: `collection_memberships` collapses to one word, and `before_the_release_ships`
// stays one word rather than becoming the marker. Both are pinned negatives in the corpus.

/** A window of lines reduced to comparable prose: prefixes gone, decoration gone, spaces collapsed. */
const normalize = (lines) =>
  normalizeInline(lines.map(stripLinePrefix).join(' ')).replace(/\s+/g, ' ');

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
const toMatcher = (pattern, caseSensitive = false, source = null) =>
  new RegExp((/^\w/.test(pattern) ? '\\b' : '') + (source ?? escapeRe(pattern)), caseSensitive ? '' : 'i');

/**
 * Directories whose Markdown is a HISTORICAL record and must NOT be scanned.
 *
 * A plan or a learning legitimately says "before v0.12.0 ships, do X" — that was true when it was
 * written, and rewriting history to appease a release gate would be the wrong repair. Scanning them
 * would guarantee false positives by design.
 */
const HISTORICAL = ['docs/plans', 'docs/learnings', 'docs/superpowers'];

/**
 * Files that ARE the release record, or that a consumer reads as part of it.
 *
 * Scans every `.md` in the repo root and under `docs/` except the historical trees, rather than an
 * allowlist of individual documents. Enumerating paths one at a time is exactly how four scripts
 * drifted out of GATING.md coverage in this same PR; an exclude-list means a NEW release-facing doc
 * is covered by default, and a new historical tree announces itself as a false positive instead of
 * hiding as a silent gap. `docs/pinning.md` matters most here — it is the consumer-facing
 * release/packaging contract, named in GATING.md's release row, so a deferral there contradicts the
 * release in precisely the way this gate exists to prevent.
 */
function sourceFiles(root) {
  const out = [];
  const rel = (p) => p.slice(root.length + 1).replace(/\\/g, '/');
  const walk = (dir, mdOnly) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        if (!HISTORICAL.includes(rel(p))) walk(p, mdOnly);
      } else if (name.endsWith('.rs') || name.endsWith('.md')) {
        if (!mdOnly || name.endsWith('.md')) out.push(p);
      }
    }
  };
  walk(join(root, 'src'), false);
  walk(join(root, 'docs'), true);
  for (const name of readdirSync(root)) {
    if (name.endsWith('.md') && statSync(join(root, name)).isFile()) out.push(join(root, name));
  }
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
      // `v?` because the version is written both ways in this repo's prose. Decoration around it
      // (`` `v0.15.0` ``, `**v0.15.0**`) is already gone by the time this matches — see normalize().
      // `v?` because the repo writes it both ways, and optional parens because those survive
      // normalization on purpose (the annotation marker needs its own `(`). Brackets do not need
      // covering here — normalizeInline already turned those into spaces.
      source: `before \\(?v?${escapeRe(version)}\\)? ships`,
      why: `work deferred until v${version}, which is the release being cut`,
      // Same ambiguity as the prose temporal marker: "the migration is complete before v0.15.0
      // ships" is a statement of fact, not a deferral.
      needsCue: true,
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
    re: toMatcher(m.pattern, m.caseSensitive, m.source),
    firstWordRe: toMatcher(m.pattern.split(' ')[0], m.caseSensitive),
  }));
  for (let i = 0; i < lines.length; i++) {
    const window = normalize(lines.slice(i, i + 3));
    for (const m of compiled) {
      if (!m.re.test(window)) continue;
      // An ambiguous temporal phrase needs imperative/pending language in the same window, or
      // ordinary documentation describing finished behaviour would block every release.
      if (m.needsCue && !DEFERRAL_CUE.test(window)) continue;
      // Report the line the marker actually STARTS on, not the window's first line — a release
      // gate that points at the wrong line costs whoever is debugging it more than it saves.
      // Matched against the NORMALIZED line, or a decorated/`///`-prefixed first line would fail
      // the attribution search and the hit would be blamed on the window's opening line instead.
      let at = i;
      for (let j = i; j < Math.min(i + 3, lines.length); j++) {
        if (m.firstWordRe.test(normalize([lines[j]]))) {
          at = j;
          break;
        }
      }
      // Explicit exemption on the hit's own line or the one above it (eslint-disable-next-line
      // semantics), so an author can keep prose the cue heuristic misjudges.
      if (lines[at].includes(ALLOW_TOKEN) || (at > 0 && lines[at - 1].includes(ALLOW_TOKEN))) continue;
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
  // The EVASION CORPUS. Every case here is a way a real deferral marker could hide from a naive
  // matcher, and most of these classes were found by review rather than by me — so this list, not
  // the fixes above, is the durable answer. Add a row here FIRST whenever a new evasion is imagined;
  // it runs in CI ahead of the scan, so the corpus can never silently stop being checked.
  const cases = [
    // -- plain --
    ['/// TUNE(SUR-1019 step 8a): provisional', true],
    ['the value is provisional pending the device pass', true],
    ['re-derive this before v9.9.9 ships', true],
    ['re-derive it before   the   release   ships', true],               // whitespace noise
    // -- capitalization: prose opens sentences with a capital --
    ['Provisional pending the device pass against the real model.', true],
    ['Before v9.9.9 ships, re-run the device pass.', true],
    ['PROVISIONAL PENDING the device pass', true],
    // -- Markdown decoration: this repo's own CHANGELOG writes versions as inline code --
    ['re-derive it before `v9.9.9` ships', true],
    ['re-derive it before **v9.9.9** ships', true],
    ['re-derive it before *v9.9.9* ships', true],
    ['re-derive it before ***v9.9.9*** ships', true],
    ['re-derive it before 9.9.9 ships', true],                           // version without the v
    ['deferred until before **the release** ships', true],               // emphasis INSIDE a phrase
    ['the value is _provisional pending_ the device pass', true],        // underscore also broke \b
    ['the value is `provisional pending` the device pass', true],
    // -- Markdown STRUCTURE, not just emphasis: the decoration sits BETWEEN the words --
    ['re-derive it before [v9.9.9](https://example.invalid) ships', true],     // inline link
    ['re-derive it before [v9.9.9][rel] ships', true],                         // reference link
    ['re-derive it before ![v9.9.9](img.png) ships', true],                    // image syntax
    ['re-derive it before [v9.9.9] ships', true],                              // bare brackets
    ['re-derive it before (v9.9.9) ships', true],                              // wrapping parens
    ['re-derive it before <code>v9.9.9</code> ships', true],                   // inline HTML
    ['re-derive it before <b>v9.9.9</b> ships', true],
    ['| step | re-derive it before v9.9.9 ships |', true],                     // table row
    ['re-derive it before&nbsp;v9.9.9 ships', true],                           // HTML entity
    ['re-derive it before <https://x.invalid> v9.9.9 ships', true],            // autolink between words
    ['re-run it before the release <!-- editor note --> ships', true],          // HTML comment
    ['re-run it before the release[^1] ships', true],                           // footnote INSIDE the phrase
    ['the value is [provisional pending](x) the device pass', true],            // linked prose marker
    // -- wrapped across a line break, carrying the continuation line's own prefix --
    ['must re-derive from distributions before the release\n   ships (the constant sits', true],
    ['/// re-derive the value before the release\n/// ships and then stop', true],
    ['//! re-derive the value before the release\n//! ships and then stop', true],
    ['// re-derive the value before the release\n// ships and then stop', true],
    ['/* re-derive before the release\n * ships */', true],
    ['> re-derive before the release\n> ships now', true],
    ['- re-derive before the release\n  ships now', true],
    ['# re-run it before the release\n# ships', true],
    // -- ordinary release DOCUMENTATION describing finished behaviour: a temporal phrase alone
    //    is not evidence, and firing on these would block every release over correct prose --
    ['CI verifies the checksums before the release ships', false],
    ['The migration is complete before v9.9.9 ships.', false],
    ['Every artifact is SHA-256 pinned before the release ships.', false],
    // -- ...but the same phrase WITH imperative/pending language is a real deferral --
    ['re-derive this value before v9.9.9 ships', true],
    ['you must bump the pin before the release ships', true],
    ['this is still outstanding before v9.9.9 ships', true],
    ['the release gate re-derives this before v9.9.9 ships', true],   // the real incident's shape
    // -- explicit exemption, on the line and the line above (eslint-disable-next-line semantics) --
    ['re-derive this before v9.9.9 ships <!-- stale-marker-allow -->', false],
    // Template literals so a real newline needs no escaping — these are multi-line by nature.
    [`<!-- stale-marker-allow -->
re-derive this before v9.9.9 ships`, false],
    [`<!-- stale-marker-allow -->
filler line, so the exemption is two lines above
re-derive this before v9.9.9 ships`, true], // an exemption must not leak down the file
    // -- must NOT trip: ordinary code, and prose that merely contains a marker substring --
    ['fn tune(x: f64) -> f64 { x }', false],
    ['let y = self.tune(0.5);', false],
    ['let seed = fortune(rng);', false],
    ['fn attune(&self) -> f64 { 0.0 }', false],
    ['`collection_memberships` converge to ONE row', false],
    ['relationships between notes are row-per-edge', false],
    ['the release ships an additive API', false],
    ['let before_the_release_ships = true;', false],  // stripping decoration must not forge a phrase
    ['ranking policy is core-owned and version-pinned', false],
    // -- the accepted miss, pinned as a decision: a lowercase annotation is not the convention --
    ['/// Tune(SUR-1019): still outstanding', false],
    ['/// Tune(SUR-1019): provisional pending the device pass', true],
  ];
  let ok = true;
  for (const [text, shouldTrip] of cases) {
    const tripped = findMarkers(text, '9.9.9').length > 0;
    if (tripped !== shouldTrip) {
      console.error(`self-check FAILED: expected trip=${shouldTrip} for: ${text}`);
      ok = false;
    }
  }
  // WHICH FILES get scanned is filesystem logic, so the string corpus above cannot reach it — and
  // an unpinned behaviour is an unverified claim. Build a throwaway tree instead and assert the two
  // properties that matter: release-facing docs are IN, historical trees are OUT. Without the second
  // one, every plan document that legitimately recorded a past deferral would block releases.
  const tmp = mkdtempSync(join(tmpdir(), 'stale-marker-selfcheck-'));
  try {
    for (const d of ['src', 'docs/adr', 'docs/plans', 'docs/learnings', 'docs/superpowers']) {
      mkdirSync(join(tmp, ...d.split('/')), { recursive: true });
    }
    for (const f of ['README.md', 'CHANGELOG.md', 'docs/pinning.md', 'docs/snapshots.md',
      'docs/adr/0001-x.md', 'src/lib.rs', 'docs/plans/old.md', 'docs/learnings/old.md',
      'docs/superpowers/old.md']) {
      writeFileSync(join(tmp, ...f.split('/')), '# placeholder\n');
    }
    const scanned = sourceFiles(tmp).map((p) => p.slice(tmp.length + 1).split('\\').join('/'));
    const mustInclude = ['README.md', 'CHANGELOG.md', 'docs/pinning.md', 'docs/snapshots.md',
      'docs/adr/0001-x.md', 'src/lib.rs'];
    const mustExclude = ['docs/plans/old.md', 'docs/learnings/old.md', 'docs/superpowers/old.md'];
    for (const f of mustInclude) {
      if (!scanned.includes(f)) {
        console.error(`self-check FAILED: ${f} must be scanned (it is release-facing)`);
        ok = false;
      }
    }
    for (const f of mustExclude) {
      if (scanned.includes(f)) {
        console.error(`self-check FAILED: ${f} must NOT be scanned (historical record)`);
        ok = false;
      }
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
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
