#!/usr/bin/env node
// Fail a release that still carries a marker deferring work UNTIL that release (SUR-1019 follow-up).
//
// The gap this closes, from the v0.14.0 cut: merging a PR onto a squash-merged base re-inserted the
// OLD paragraph after the NEW one in every file it touched, so `src/fusion.rs`, ADR 0007, and the
// CHANGELOG each simultaneously recorded a measured constant AND instructed maintainers to
// "re-derive this value ... before v0.14.0 ships". Nothing objected: `release.yml` verifies the
// CHANGELOG section *heading* and the crate version, never the prose beneath them.
//
// THREAT MODEL — read this before filing an evasion finding. This gate defends against ACCIDENTAL
// staleness: honestly written deferral prose that survived into a release commit, in the shapes
// maintainers actually write (wrapped doc comments, sentence capitals, house-style `**bold**` /
// `` `code` `` versions, plain links, tables). It does NOT defend against adversarial concealment —
// a marker hidden behind character references, escaped delimiters, exotic link grammar, or any
// other decoration nobody types by accident. A maintainer who wants to hide a deferral from this
// gate can simply not write the marker; resisting adversarial Markdown means reimplementing a
// CommonMark renderer inside a release script, and an earlier revision of this file proved that
// road has no end (35 review findings, each locally valid, the series divergent). Accepted misses
// are pinned as explicit corpus rows below so the boundary is executable, not folklore.
//
// Deliberately narrow. This gates ONE class — a deferral pointing at the release being cut — not
// code hygiene. `TODO`/`FIXME` are ordinary and are not checked: a gate that fires on things
// people reasonably ship is a gate people learn to bypass.
//
// Usage:  node scripts/check-stale-release-markers.mjs [<version>]
//         node scripts/check-stale-release-markers.mjs --self-check

import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Markers that always mean "not finished yet", wherever they appear. They fire UNCONDITIONALLY,
// descriptive prose included ("CI verifies the checksums before the release ships" trips): an
// earlier cue heuristic that tried to wave descriptive uses through failed open on any imperative
// verb outside its allowlist — an open class. A release gate fails CLOSED; a false positive is
// visible and costs a one-line `stale-marker-allow`, a false negative ships silently.
//
// `TUNE(` is an ANNOTATION, uppercase by convention like TODO(: its case IS its syntax, so it is
// matched case-sensitively or every ordinary Rust `fn tune(..)` would block a release. The rest
// are PROSE, where a sentence-opening capital is ordinary writing: case-insensitive. The
// provisional pair takes a short punctuation bridge ("provisional, pending", "provisional
// (pending") but never a sentence boundary — `.` is absent from the class.
const STATIC_MARKERS = [
  { pattern: 'TUNE(', why: 'a TUNE(...) deferral marker', caseSensitive: true },
  {
    pattern: 'provisional pending',
    source: 'provisional[\\s,;:(\\u2013\\u2014-]{1,3}pending',
    why: 'a value still labelled provisional',
  },
  { pattern: 'before the release ships', why: 'work deferred to release time' },
];

/**
 * Escape hatch: a line carrying this token, or the line directly above it, is exempt — the
 * `eslint-disable-next-line` contract. This is what lets the markers fail closed: descriptive
 * prose that legitimately uses a temporal phrase keeps a one-line exemption, visible in review,
 * which a silent miss is not.
 */
const ALLOW_TOKEN = 'stale-marker-allow';

/** Escape a literal so it can be embedded in a RegExp — the version's dots especially. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Strip a line's leading comment / quote / list decoration. Without this, ANY wrapped marker in a
 * Rust doc comment escapes: `/// … before the release` + `/// ships …` joins to "… release ///
 * ships". Doc comments wrap at ~100 cols throughout this crate — this was the real incident's
 * shape. Ordered-list prefixes (`1.`) are deliberately NOT stripped: a line opening with `0.15.0`
 * would lose its `0.` and stop matching the version marker.
 */
const stripLinePrefix = (line) => line.replace(/^\s*(\/\/\/|\/\/!|\/\/|\/\*+|\*+\/|\*|#+|>+|[-+])\s*/, ' ');

/**
 * Reduce a line to the prose a reader sees, for the shapes this repo actually writes: versions as
 * `` `code` `` or `**bold**` (house style), plain inline/reference links, tables, the odd entity
 * or HTML tag. Emphasis deletion only ever DELETES, so it cannot forge a phrase out of an
 * identifier (`before_the_release_ships` stays one word). Table pipes are KEPT: a pipe separates
 * — as a cell boundary or a visible character — and spacing it would join adjacent cells into a
 * phrase no reader sees.
 */
const normalizeInline = (s) =>
  s
    // No HTML-comment rule here: a comment legally spans lines, so findMarkers blanks comments on
    // the WHOLE text before any per-line work — a rule at this level can never see one.
    .replace(/\[\^[^\]]*\]/g, ' ') // footnote refs, before the link rules claim the brackets
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1') // images + inline links -> visible label
    .replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1') // reference links -> visible label
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ') // HTML tags + autolinks -> separation
    .replace(/&[a-zA-Z]+;|&#\w+;/g, ' ') // character references -> separation
    .replace(/[[\]]/g, ' ') // leftover brackets (pipes deliberately kept)
    .replace(/[`*_~]/g, ''); // emphasis / code / strikethrough delimiters

/** A line reduced to comparable prose: prefix gone, decoration gone, spaces collapsed. */
const normalizeLine = (line) => normalizeInline(stripLinePrefix(line)).replace(/\s+/g, ' ').trim();

/**
 * Compile a marker to a matcher: word-boundary anchored, case per the marker, always global (the
 * exec loop runs to exhaustion, which is also what resets it between paragraphs).
 */
const toMatcher = (pattern, caseSensitive = false, source = null) =>
  new RegExp((/^\w/.test(pattern) ? '\\b' : '') + (source ?? escapeRe(pattern)), caseSensitive ? 'g' : 'gi');

/**
 * Directories whose Markdown is a HISTORICAL record and must NOT be scanned: a plan legitimately
 * says "before v0.12.0 ships, do X" — true when written, and rewriting history to appease a gate
 * would be the wrong repair. The rule: immutable records are out, living documents are in (ADRs
 * are living — amended with supersede notes — so they stay in scope).
 */
const HISTORICAL = ['docs/plans', 'docs/learnings', 'docs/superpowers'];

/**
 * Every `.rs` under src/, every `.md` under docs/ (minus historical trees) and the repo root.
 * An exclude-list, not an allowlist: a NEW release-facing doc is covered by default.
 */
function sourceFiles(root) {
  const out = [];
  const rel = (p) => p.slice(root.length + 1).replace(/\\/g, '/');
  const walk = (dir, mdOnly) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return; // a missing tree is not this gate's business
    }
    for (const name of entries) {
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

/**
 * Blank every changelog line outside `[Unreleased]` and the section being cut. A shipped release
 * entry is an IMMUTABLE record — an entry that accurately recorded a then-provisional value must
 * never block a future release, and the only way to clear it would be editing shipped history.
 * Lines are blanked rather than removed so reported line numbers stay true. A `## [x.y.z]` line
 * inside a FENCED example is prose quoting a heading, not a section boundary — treating it as
 * real would mask the rest of [Unreleased] and fail open.
 */
function maskReleasedChangelogSections(text, version) {
  const lines = text.split('\n');
  let active = true; // the file preamble, before any section heading
  let fence = null; // the opening delimiter of the fence we are inside, if any
  return lines
    .map((line) => {
      // A fence closes only on AT LEAST the opener's length in the same character — CommonMark's
      // rule, and what lets a ```` block quote a ``` snippet without the state desyncing.
      const f = /^\s*(`{3,}|~{3,})/.exec(line);
      if (f) {
        if (!fence) fence = f[1];
        else if (f[1][0] === fence[0] && f[1].length >= fence.length) fence = null;
      }
      const heading = !fence && /^##\s+\[([^\]]+)\]/.exec(line);
      if (heading) {
        const label = heading[1].trim().toLowerCase();
        active = label === 'unreleased' || (!!version && label === version.toLowerCase());
      }
      return active ? line : '';
    })
    .join('\n');
}

/** Every marker hit in `text`, as {line, why, excerpt}. `version` may be undefined. */
export function findMarkers(text, version) {
  const markers = [...STATIC_MARKERS];
  if (version) {
    markers.push({
      pattern: `before v${version} ships`,
      // The honest spellings: bare, `v`-prefixed, `version 0.15.0`, `the 0.15.0 release`; parens
      // tolerated because normalization keeps them (the annotation marker needs its own `(`).
      source: `before (?:the )?\\(?(?:version )?v?${escapeRe(version)}\\)?(?: release)? ships`,
      why: `work deferred until v${version}, which is the release being cut`,
    });
  }
  const rawLines = text.split('\n');
  // HTML comments are blanked whole-text with newlines kept: an editor note legally spans lines,
  // even mid-phrase ("before the release <!-- note\n--> ships" renders the marker). Raw lines
  // keep serving the allow-token check — the token's own carrier is a comment — and identical
  // line counts keep the two aligned.
  const blanked = text.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' ')).split('\n');
  const segs = blanked.map(normalizeLine);
  const mdBody = (l) => l.replace(/^\s*(?:\/\/\/|\/\/!|\/\/)\s?/, '');

  // Markers are matched against PARAGRAPH RUNS, not single lines: prose wraps at ~100 cols, so a
  // marker routinely straddles a line break — the real ADR 0007 case was "before the release\n
  // ships". A run ends where the reader sees separation: a line with no content (blank,
  // prefix-only `///`, decoration-only — a bare ``` fence normalizes to nothing and lands here
  // too, while an info string like ```rust becomes a token no phrase spans), a heading (a block
  // of exactly itself), or a line starting a new bullet / ordered item / blockquote. Lazy
  // continuations and consecutive `>` lines keep joining — those render as one paragraph.
  const isHeading = (l) => /^\s*#{1,6}\s/.test(mdBody(l));
  const isQuote = (l) => /^\s*>/.test(mdBody(l));
  const startsBlock = (j) =>
    /^\s*(?:[-+]\s|\d+[.)]\s)/.test(mdBody(rawLines[j])) ||
    (isQuote(rawLines[j]) && !(j > 0 && isQuote(rawLines[j - 1])));
  const runs = [];
  let run = [];
  const flush = () => {
    if (run.length) runs.push(run);
    run = [];
  };
  for (let j = 0; j < rawLines.length; j++) {
    if (segs[j] === '') {
      // A content-empty line closes the run — EXCEPT one swallowed whole by a multiline comment
      // (raw text had content, blanked line is empty): the comment renders as nothing, so the
      // phrase around it must stay joined.
      if (blanked[j].trim() !== '' || rawLines[j].trim() === '') flush();
    } else if (isHeading(rawLines[j])) {
      flush();
      runs.push([j]);
    } else {
      if (startsBlock(j)) flush();
      run.push(j);
    }
  }
  flush();

  const compiled = markers.map((m) => ({ ...m, re: toMatcher(m.pattern, m.caseSensitive, m.source) }));
  const seen = new Set();
  const hits = [];
  for (const idx of runs) {
    // Lines join with recorded start offsets, so a match index maps straight back to the source
    // line — searching for a marker's first word would blame any earlier line containing an
    // ordinary word like "before".
    const starts = [];
    let joined = '';
    for (const j of idx) {
      if (joined) joined += ' ';
      starts.push(joined.length);
      joined += segs[j];
    }
    for (const m of compiled) {
      for (let hit; (hit = m.re.exec(joined)); ) {
        let at = idx[0];
        for (let k = starts.length - 1; k >= 0; k--) {
          if (hit.index >= starts[k]) {
            at = idx[k];
            break;
          }
        }
        if (rawLines[at].includes(ALLOW_TOKEN) || (at > 0 && rawLines[at - 1].includes(ALLOW_TOKEN))) continue;
        const key = `${m.pattern}@${at}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({ line: at + 1, why: m.why, excerpt: rawLines[at].trim().slice(0, 120) });
      }
    }
  }
  return hits;
}

function selfCheck() {
  // The corpus IS the contract: the honest shapes that must trip, the ordinary code and prose
  // that must not, and the ACCEPTED MISSES that make the threat-model boundary executable.
  const cases = [
    // -- the incident's own shapes --
    ['/// TUNE(SUR-1019 step 8a): provisional', true],
    ['the value is provisional pending the device pass', true],
    ['re-derive this before v9.9.9 ships', true],
    ['the release gate re-derives this before v9.9.9 ships', true],
    // -- honest writing variants --
    ['Before v9.9.9 ships, re-run the device pass.', true], // sentence capital
    ['PROVISIONAL PENDING the device pass', true],
    ['This threshold is provisional, pending the real-device pass.', true], // punctuation bridge
    ['This threshold is provisional (pending the device pass)', true],
    ['re-derive it before   the   release   ships', true], // whitespace noise
    ['re-derive it before `v9.9.9` ships', true], // house style: version as inline code
    ['re-derive it before **v9.9.9** ships', true], // ...or bold
    ['re-derive it before 9.9.9 ships', true], // version without the v
    ['Remove this shim before version 9.9.9 ships.', true], // version as a noun phrase
    ['Remove this shim before the v9.9.9 release ships.', true], // "release" after the version
    ['re-derive it before [v9.9.9](https://example.invalid) ships', true], // house style: linked
    ['re-derive it before [v9.9.9][rel] ships', true],
    ['| step | re-derive it before v9.9.9 ships |', true], // phrase inside ONE table cell
    // -- fail-closed: descriptive prose fires too, and keeps an allow-token when legitimate --
    ['CI verifies the checksums before the release ships', true],
    // -- wrapped across a line break, carrying the continuation line's own prefix --
    ['must re-derive from distributions before the release\n   ships (the constant sits', true],
    ['/// re-derive the value before the release\n/// ships and then stop', true],
    ['//! re-derive the value before the release\n//! ships and then stop', true],
    ['// re-derive the value before the release\n// ships and then stop', true],
    ['/* re-derive before the release\n * ships */', true],
    ['> re-derive before the release\n> ships now', true],
    ['- re-derive before the release\n  ships now', true], // lazy continuation joins
    ['/// re-derive before\n/// the\n/// release\n/// ships now', true], // a run has no line cap
    // -- an editor note renders as nothing, wherever its lines fall --
    ['re-run it before the release <!-- editor note --> ships', true],
    ['Remove this before the release <!-- editor note\nkeep until migration lands\n--> ships', true],
    // -- the reader's separations must keep separating: no phrase forged across them --
    ['must re-derive before the release\n\nships now', false], // paragraph break
    ['/// Complete setup before the release\n///\n/// Ships are signed', false], // prefix-only break
    ['- Complete setup before the release\n- Ships are signed and uploaded.', false], // two bullets
    ['## Notes on before the release\nships an additive API', false], // heading is its own block
    ['re-derive before the release\n> ships now', false], // quote entry starts a block
    ['must re-derive before the release\n```\nships are signed\n```', false], // fence bounds
    ['```rust\n/// TUNE(SUR-1019): provisional pending x\n```', true], // ...but its contents scan
    ['| before the release | ships are signed |', false], // adjacent table cells
    // ACCEPTED OVER-MATCH, recorded as a decision: `*` cannot be a block boundary because it is
    // also the block-comment continuation prefix, where JOINING is what catches a wrapped marker
    // (the `/* … * ships */` positive above) — splitting on `*` would trade that incident-class
    // miss for this contrived false positive. House bullets are `-`; if a real `*`-bullet false
    // positive ever occurs, the remedy is a one-line stale-marker-allow.
    ['* re-derive before the release\n* ships now', true],
    // -- ordinary code and prose that must never trip --
    ['fn tune(x: f64) -> f64 { x }', false],
    ['let y = self.tune(0.5);', false],
    ['let seed = fortune(rng);', false],
    ['fn attune(&self) -> f64 { 0.0 }', false],
    ['`collection_memberships` converge to ONE row', false],
    ['relationships between notes are row-per-edge', false],
    ['the release ships an additive API', false],
    ['let before_the_release_ships = true;', false], // deleting emphasis must not forge a phrase
    ['The API is provisional. Pending items are tracked in Linear.', false], // sentence boundary
    ['<td>TUNE</td><td>(x)</td>', false], // tags become separation, never adjacency
    // -- explicit exemption (eslint-disable-next-line semantics) --
    ['re-derive this before v9.9.9 ships <!-- stale-marker-allow -->', false],
    ['<!-- stale-marker-allow -->\nre-derive this before v9.9.9 ships', false],
    ['<!-- stale-marker-allow -->\nfiller line\nre-derive this before v9.9.9 ships', true], // must not leak down
    // An earlier line containing an ordinary word from the marker ("before") must not steal the
    // attribution — the exemption belongs to the line the marker starts on.
    ['A sentence before anything.\n<!-- stale-marker-allow -->\nre-derive this before v9.9.9 ships', false],
    // Comment blanking must preserve LINE COUNT, or every raw-line lookup below a multiline
    // comment (allow token, excerpt) shifts onto the wrong line.
    ['<!-- an\neditor\nnote -->\n<!-- stale-marker-allow -->\nre-derive this before v9.9.9 ships', false],
    // -- ACCEPTED MISSES: adversarial concealment is out of threat model (see header). These rows
    //    pin the boundary; flipping one to true is a deliberate scope change, not a bug fix. --
    ['re-derive it bef&#x6f;re v9.9.9 ships', false], // character reference spelling a letter
    ['re-derive it be<em>fore</em> v9.9.9 ships', false], // formatting tag inside a word
    ['re-derive before [the release](https://x.invalid/a_(b)) ships', false], // exotic link grammar (nested parens)
    // -- the accepted lowercase-annotation miss, pinned as a decision --
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

  // WHICH FILES get scanned is filesystem logic the string corpus cannot reach; pin it on a
  // throwaway tree: release-facing docs are IN, historical trees are OUT.
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
    for (const f of ['README.md', 'CHANGELOG.md', 'docs/pinning.md', 'docs/snapshots.md',
      'docs/adr/0001-x.md', 'src/lib.rs']) {
      if (!scanned.includes(f)) {
        console.error(`self-check FAILED: ${f} must be scanned (it is release-facing)`);
        ok = false;
      }
    }
    for (const f of ['docs/plans/old.md', 'docs/learnings/old.md', 'docs/superpowers/old.md']) {
      if (scanned.includes(f)) {
        console.error(`self-check FAILED: ${f} must NOT be scanned (historical record)`);
        ok = false;
      }
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // Changelog scoping, driven through scanRepo() so the WIRING is pinned, not just the function.
  // The fenced fake heading inside [Unreleased] pins fence-awareness: treated as real, it would
  // mask the rest of the section and fail open.
  const changelog = [
    '# Changelog', '', '## [Unreleased]', '',
    '````', '```', '## [0.0.1] - a quoted example, not a section', '```', '````', '',
    'UNRELEASED', '',
    '## [9.9.9] - 2026-01-01', '', 'CUTTING', '',
    '## [9.9.8] - 2025-12-01', '', 'SHIPPED', '',
  ].join('\n');
  const stale = 'the threshold was provisional pending field results';
  const sectionCases = [
    ['SHIPPED', false, 'a shipped section is immutable history'],
    ['UNRELEASED', true, '[Unreleased] is asserted by this release'],
    ['CUTTING', true, 'the section being cut is asserted by this release'],
  ];
  for (const [slot, shouldTrip, why] of sectionCases) {
    const dir = mkdtempSync(join(tmpdir(), 'stale-marker-changelog-'));
    try {
      mkdirSync(join(dir, 'src'), { recursive: true });
      writeFileSync(join(dir, 'src', 'lib.rs'), '// nothing\n');
      writeFileSync(join(dir, 'CHANGELOG.md'), changelog.replace(slot, stale));
      const tripped = scanRepo(dir, '9.9.9').length > 0;
      if (tripped !== shouldTrip) {
        console.error(`self-check FAILED: ${slot} — ${why} (expected trip=${shouldTrip})`);
        ok = false;
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  console.log(ok ? 'check-stale-release-markers: self-check OK' : 'self-check FAILED');
  process.exit(ok ? 0 : 1);
}

/**
 * Scan a repository root and return every hit as `{file, line, why, excerpt}`. A function rather
 * than top-level code so `--self-check` exercises the REAL path against a throwaway tree —
 * testing a helper directly proves the unit works while a deleted call site still passes.
 */
export function scanRepo(root, version) {
  const hits = [];
  for (const file of sourceFiles(root)) {
    let text;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    if (file.endsWith('CHANGELOG.md')) text = maskReleasedChangelogSections(text, version);
    for (const hit of findMarkers(text, version)) {
      hits.push({ ...hit, file: file.slice(root.length + 1).replace(/\\/g, '/') });
    }
  }
  return hits;
}

const arg = process.argv[2];
if (arg === '--self-check') selfCheck();

const version = arg && arg !== '--self-check' ? arg.replace(/^v/, '') : undefined;
const found = scanRepo(process.cwd(), version);
for (const hit of found) {
  console.error(`::error file=${hit.file},line=${hit.line}::${hit.why} — ${hit.excerpt}`);
}
if (found.length > 0) {
  console.error(
    `\ncheck-stale-release-markers: ${found.length} stale marker(s). The release would ship ` +
      `documentation telling maintainers to redo work this release already contains. ` +
      `Resolve each marker (or delete it if the work is done) and re-tag.`,
  );
  process.exit(1);
}
console.log(
  `check-stale-release-markers: OK — no deferral markers${version ? ` for v${version}` : ''}`,
);
