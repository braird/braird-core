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
  {
    pattern: 'provisional pending',
    // A short bridge of punctuation/whitespace is the same deferral: "provisional, pending the
    // device pass", "provisional — pending", and the parenthetical "provisional (pending …)"
    // all read identically to the bare pair. A sentence boundary does NOT bridge (`.` is absent
    // from the class): "The API is provisional. Pending items…" is two unrelated statements and
    // must not join.
    source: 'provisional[\\s,;:(\\u2013\\u2014-]{1,3}pending',
    why: 'a value still labelled provisional',
  },
  { pattern: 'before the release ships', why: 'work deferred to release time' },
];

// The temporal markers fire UNCONDITIONALLY, descriptive prose included. An earlier revision
// required an imperative/pending "cue" word nearby, so that "CI verifies the checksums before the
// release ships" would pass as a statement of finished behaviour — but imperative English is an
// open class ("Remove this compatibility shim before v9.9.9 ships" carries no cue any list would
// think to name), so the allowlist silently failed OPEN on every verb it didn't know, and each
// review round found another. A release gate carries the opposite duty: fail CLOSED and make the
// operator decide. A false positive is visible and costs a one-line `stale-marker-allow`; a false
// negative ships self-contradicting docs with no trace. The cue machinery, its sentence splitter,
// and their corpus rows were deleted rather than extended.

/**
 * Escape hatch for the residual: a line carrying this token, or the line directly above it, is
 * exempt — the `eslint-disable-next-line` contract. This is what lets the markers fail closed:
 * descriptive prose that legitimately uses a temporal phrase, a quoted spec, or a historical note
 * in a live document keeps a one-line exemption instead of blocking the release. An exemption is
 * visible in review, which a silent miss is not.
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
    // No HTML-comment rule here: comments can span lines, so findMarkers blanks them on the whole
    // text before any per-line work — a rule at this level was mutation-tested as redundant.
    .replace(/\[\^[^\]]*\]/g, ' ') // footnote refs, before the link rules claim the brackets
    // Images + inline links -> visible label. The destination may be angle-bracketed
    // (`(<https://a_(b)>)`, CommonMark's escape for awkward URLs) or a plain URL with one level of
    // balanced parens (`https://en.wikipedia.org/wiki/A_(b)`) — both are valid forms where a naive
    // `[^)]*` stops at the destination's own `)` and leaves debris inside the phrase.
    .replace(/!?\[([^\]]*)\]\((?:<[^>]*>)?(?:[^()]|\([^()]*\))*\)/g, '$1')
    .replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1') // reference links -> visible label
    // The split between the next two rules is what the RENDERED text demands. Inline FORMATTING
    // tags contribute no whitespace — `be<em>fore</em>` reads "before", so a space would split the
    // word and hide the marker; they are deleted outright. Everything else — block and void
    // elements, autolinks, unknown tags — becomes a space, because those DO render as separation
    // and deleting them would forge joined-up text out of adjacent table cells (`<td>TUNE</td>
    // <td>(x)</td>` must not become `TUNE(x)`). A `<br>` mid-phrase thus joins with a space, the
    // same semantics the paragraph join gives a hard line wrap. No separate autolink rule:
    // `<https://…>` is consumed by the generic rule, mutation-tested as redundant rather than assumed.
    .replace(/<\/?(?:em|strong|b|i|code|span|sub|sup|u|s|small|abbr|mark|kbd|a)(?:\s[^>]*)?\s*\/?>/gi, '')
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ')
    // Numeric character references DECODE to their character: `bef&#x6f;re` renders as "before",
    // so blanking to a space would split the word and hide the marker. Decimal and hex (either
    // case marker) are both decoded; out-of-range codepoints blank rather than throw.
    .replace(/&#(\d+);/g, (_, d) => (+d <= 0x10ffff ? String.fromCodePoint(+d) : ' '))
    .replace(/&#[xX]([0-9a-fA-F]+);/g, (_, h) => (parseInt(h, 16) <= 0x10ffff ? String.fromCodePoint(parseInt(h, 16)) : ' '))
    // NAMED references split by what they can spell. HTML names none of the bare ASCII letters,
    // but it does name PUNCTUATION — `v9&period;9&period;9` renders "v9.9.9" — so every named
    // reference for a character that can appear inside a marker (the version's dot, the
    // annotation's parens, the provisional pair's bridge punctuation) decodes via this map. All
    // other names blank to a space: they can separate words but never spell one (accepted
    // residue: ligature oddities like `&fjlig;` render letter PAIRS, none inside a marker word).
    .replace(/&(period|lpar|rpar|comma|colon|semi|ndash|mdash);/g,
      (_, n) => ({ period: '.', lpar: '(', rpar: ')', comma: ',', colon: ':', semi: ';', ndash: '–', mdash: '—' }[n]))
    .replace(/&[a-zA-Z][a-zA-Z0-9]*;/g, ' ')
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
 *
 * Always global: the scan must see EVERY occurrence in a paragraph, not the first. The statefulness a
 * `g` regex carries is safe here because every exec loop runs to exhaustion, which resets it.
 */
const toMatcher = (pattern, caseSensitive = false, source = null) =>
  new RegExp((/^\w/.test(pattern) ? '\\b' : '') + (source ?? escapeRe(pattern)), caseSensitive ? 'g' : 'gi');

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
    // A missing tree is not this gate's business, the same tolerance the CHANGELOG read already has.
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
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
 * Blank every changelog line outside `[Unreleased]` and the section being cut.
 *
 * A shipped release entry is an IMMUTABLE historical record — the same argument that keeps
 * `docs/plans` and `docs/learnings` out of scope, and this file is the most historical one in the
 * repo: 26 released sections, ~1500 lines. An entry that accurately recorded a then-provisional
 * value ("the threshold was provisional pending field results") would otherwise block every future
 * release, and the only way to clear it would be editing shipped release history — which is exactly
 * the wrong repair. Scoping this checker to what the release actually asserts is the fix.
 *
 * The distinction the whole scan now rests on: **immutable records are out, living documents are
 * in.** Released changelog sections, plans and learnings are immutable. ADRs are living — they get
 * amended with supersede notes rather than frozen (ADR 0006 was amended, not left stale), and the
 * incident this gate exists for was partly IN an ADR — so they stay fully in scope.
 *
 * Lines are blanked rather than removed so reported line numbers stay true and a paragraph run can
 * never straddle a section boundary.
 */
function maskReleasedChangelogSections(text, version) {
  const lines = text.split('\n');
  let active = true; // the file preamble, before any section heading
  return lines
    .map((line) => {
      const heading = /^##\s+\[([^\]]+)\]/.exec(line);
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
    // The version-specific form — "before v0.14.0 ships". A bare "ships" is useless here: it is a
    // substring of `memberships`/`relationships`, which appear 150+ times in legitimate prose.
    markers.push({
      pattern: `before v${version} ships`,
      // The number may be written bare (`0.15.0`), `v`-prefixed, or as a noun phrase on either
      // side (`version 0.15.0`, `the 0.15.0 release`) — all of which appear in ordinary
      // maintainer prose. Optional parens because those survive normalization on purpose (the
      // annotation marker needs its own `(`); decoration and brackets are already gone by the
      // time this matches — see normalize().
      source: `before (?:the )?\\(?(?:version )?v?${escapeRe(version)}\\)?(?: release)? ships`,
      why: `work deferred until v${version}, which is the release being cut`,
    });
  }
  // Scan paragraph by paragraph with whitespace collapsed, never line by line: a marker routinely
  // straddles a line break — the real ADR 0007 case was "before the release\n   ships", which
  // every single-line check walks straight past.
  //
  // HTML comments are blanked up front with newlines kept, so a comment can never shield part of a
  // phrase — including one spanning a line break, which the per-line normalization below cannot
  // see. Matching runs on the blanked copy; the RAW lines keep serving the allow-token check (the
  // token itself lives inside a comment) and the reported excerpt, and identical line counts keep
  // the two aligned.
  const rawLines = text.split('\n');
  const lines = text.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' ')).split('\n');
  const seen = new Set();
  const hits = [];
  const compiled = markers.map((m) => ({ ...m, re: toMatcher(m.pattern, m.caseSensitive, m.source) }));
  // Each line is normalized SEPARATELY and joined with its start offset recorded, so a match
  // index maps straight back to the source line. The previous attribution — searching lines for
  // the marker's first word — blamed the nearest earlier line containing an ordinary word like
  // "before", which both misreported the line and pointed the allow-token check above the wrong
  // one, turning an explicitly exempted marker into a release blocker.
  const segsAll = lines.map((l) => normalize([l]).trim());
  // Markers are matched against whole rendered PARAGRAPHS, not a fixed-size window. Prose wraps
  // at ~100 cols and a doc comment can legally put every word of a phrase on its own line, so any
  // fixed line cap is an evasion exactly that many lines long. A paragraph run is a maximal
  // stretch of content-bearing lines: a raw-blank line closes it (the reader sees separated
  // prose, so "before the release" ending one paragraph never joins "ships …" opening the next),
  // while a line swallowed whole by a comment is skipped WITHOUT closing it (it renders nothing,
  // and a long comment must not split the phrase around it).
  //
  // Markdown also starts a new block WITHOUT a blank line: a heading, a list item, or the first
  // line of a blockquote each render as their own block, and joining across that boundary would
  // manufacture a phrase no reader sees ("- Complete setup before the release" + "- Ships are
  // signed" must not become one sentence). So a heading is a run of exactly its own line; a
  // bullet, ordered item, or quote-entry line closes the run before itself and opens a new one —
  // which keeps lazy continuations (indented follow-on text) and consecutive `>` lines joined,
  // both of which DO render as one paragraph. The comment prefix is stripped first so rustdoc
  // Markdown gets the same block structure. `*` is deliberately NOT a bullet here: it is also the
  // block-comment continuation prefix, where joining is required; the cost of that ambiguity is
  // only a possible over-match on `*`-bullets (this repo's house style is `-`), never a miss.
  const mdBody = (l) => l.replace(/^\s*(?:\/\/\/|\/\/!|\/\/)\s?/, '');
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
  for (let j = 0; j < lines.length; j++) {
    if (segsAll[j] !== '') {
      if (isHeading(rawLines[j])) {
        flush();
        runs.push([j]);
        continue;
      }
      if (startsBlock(j)) flush();
      run.push(j);
    } else if (stripLinePrefix(rawLines[j]).trim() === '') {
      // A paragraph break, in either spelling: a blank line, or a PREFIX-ONLY line (`///`,
      // `//!`, `>`) — the rustdoc/blockquote form whose raw text is non-blank but renders
      // nothing. Both close the run. The one remaining way to reach seg === '' is a line
      // swallowed by an HTML comment, whose raw text HAD content — that line is skipped with the
      // run left open, so a long comment never splits the phrase around it.
      flush();
    }
  }
  flush();
  for (const idx of runs) {
    const starts = [];
    let window = '';
    for (const j of idx) {
      if (window) window += ' ';
      starts.push(window.length);
      window += segsAll[j];
    }
    for (const m of compiled) {
      // EVERY occurrence is examined. With the cue heuristic gone this is belt-and-braces (the
      // exemption and the dedupe are both line-scoped), but running the global regex to exhaustion
      // is also what resets it between paragraphs.
      for (let hit; (hit = m.re.exec(window)); ) {
        // The line this occurrence STARTS on — the last recorded segment offset at or before it.
        let at = idx[0];
        for (let k = starts.length - 1; k >= 0; k--) {
          if (hit.index >= starts[k]) {
            at = idx[k];
            break;
          }
        }
        // Explicit exemption on the hit's own line or the one above it (eslint-disable-next-line
        // semantics), so an author can keep descriptive prose the unconditional markers misjudge.
        if (rawLines[at].includes(ALLOW_TOKEN) || (at > 0 && rawLines[at - 1].includes(ALLOW_TOKEN))) continue;
        // Dedupe on the resolved line, so a marker repeated on one line is reported once.
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
    ['Remove this shim before version 9.9.9 ships.', true],              // version as a noun phrase
    ['Remove this shim before the v9.9.9 release ships.', true],         // "release" after the version
    ['drop the fallback before the 9.9.9 release ships', true],          // ...and bare-number form
    // -- punctuation bridges the provisional pair; a sentence boundary must not --
    ['This threshold is provisional, pending the real-device pass.', true],
    ['the floor is provisional — pending the S25U pass', true],
    ['This threshold is provisional (pending the device pass)', true],
    ['The API is provisional. Pending items are tracked in Linear.', false],
    ['deferred until before **the release** ships', true],               // emphasis INSIDE a phrase
    ['the value is _provisional pending_ the device pass', true],        // underscore also broke \b
    ['the value is `provisional pending` the device pass', true],
    // -- Markdown STRUCTURE, not just emphasis: the decoration sits BETWEEN the words --
    ['re-derive it before [v9.9.9](https://example.invalid) ships', true],     // inline link
    // Angle-bracketed destination — CommonMark's escape for URLs the plain form can't hold, so the
    // pinning case uses what only it allows: an UNBALANCED paren (a balanced one is already covered
    // by the plain-destination rule and would pin nothing).
    ['re-derive it before [v9.9.9](<https://example.invalid/a_(b>) ships', true],
    // Balanced parens in a plain destination (the Wikipedia-URL shape). Pinned via the prose marker:
    // the version marker's own `\)?` tolerance would absorb the debris and mask a regression.
    ['re-derive it before [the release](https://x.invalid/wiki/A_(b)) ships', true],
    ['re-derive it before [v9.9.9][rel] ships', true],                         // reference link
    ['re-derive it before ![v9.9.9](img.png) ships', true],                    // image syntax
    ['re-derive it before [v9.9.9] ships', true],                              // bare brackets
    ['re-derive it before (v9.9.9) ships', true],                              // wrapping parens
    ['re-derive it before <code>v9.9.9</code> ships', true],                   // inline HTML
    ['re-derive it before <b>v9.9.9</b> ships', true],
    ['| step | re-derive it before v9.9.9 ships |', true],                     // table row
    ['re-derive it before&nbsp;v9.9.9 ships', true],                           // named entity
    ['re-derive it before&#32;v9.9.9 ships', true],                            // decimal char reference
    ['re-derive it before&#x20;v9.9.9 ships', true],                           // hex char reference
    ['re-derive it before&#X20;v9.9.9 ships', true],                           // ...with uppercase X
    // -- decoration INSIDE a word, not just between words: the rendered text is the marker --
    ['re-derive it be<em>fore</em> v9.9.9 ships', true],                       // formatting tag mid-word
    ['re-derive it bef&#x6f;re v9.9.9 ships', true],                           // hex reference spells a letter
    ['re-derive it bef&#111;re v9.9.9 ships', true],                           // decimal reference spells a letter
    ['re-derive it before v9&period;9&period;9 ships', true],                  // named reference spells the dot
    ['/// TUNE&lpar;SUR-1019 step 8a&rpar; needs the device pass', true],      // ...and the annotation parens
    ['re-derive it before <https://x.invalid> v9.9.9 ships', true],            // autolink between words
    ['re-run it before the release <!-- editor note --> ships', true],          // HTML comment
    [`re-run it before the release <!-- a note
spanning lines --> ships`, true],                                               // comment straddling a line break
    // A comment swallowing WHOLE lines must not push the phrase's halves out of matching range —
    // this is a rendered phrase split across five physical lines, prefixes and all.
    [`/// re-derive before the release <!-- editor
/// detail line one
/// detail line two
/// --> ships and then stop`, true],
    // -- adjacent Markdown BLOCKS are separate rendered text even without a blank line between:
    //    list items, headings, and quote entries bound the join; lazy continuations and
    //    consecutive quote lines (pinned as positives above) still join --
    ['- Complete setup before the release\n- Ships are signed and uploaded.', false],
    ['## Notes on before the release\nships an additive API', false],
    ['re-derive before the release\n> ships now', false],
    ['/// re-derive before the release\n/// - ships now', false],   // bullet inside a doc comment
    // -- a PREFIX-ONLY line is the rustdoc / blockquote spelling of a paragraph break --
    ['/// Complete setup before the release\n///\n/// Ships are signed', false],
    ['> re-derive before the release\n>\n> ships now', false],
    // ...but a real paragraph break is the reader's separation and must keep separating —
    // including a SINGLE blank line, the ordinary Markdown paragraph form, whose halves would
    // otherwise join.
    [`must re-derive before the release


ships now`, false],
    [`before the release

ships in this channel are signed`, false],
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
    // Two consecutive HEADINGS are two rendered blocks — this row was a positive when `#` was
    // treated as a mere wrapping prefix, and flipped when runs learned block structure: no reader
    // sees these five words as one phrase.
    ['# re-run it before the release\n# ships', false],
    // Every word on its own line: no fixed-size window contains this, only a paragraph scan does.
    [`/// re-derive before
/// the
/// release
/// ships now`, true],
    // -- the markers fail CLOSED: descriptive prose fires too, and keeps a stale-marker-allow if
    //    it is legitimate. The cue heuristic that tried to pass these automatically failed OPEN on
    //    any imperative verb outside its list — an open class no allowlist closes --
    ['CI verifies the checksums before the release ships', true],
    ['The migration is complete before v9.9.9 ships.', true],
    ['Remove this compatibility shim before v9.9.9 ships.', true],  // imperative with no listed cue word
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
    // An earlier line containing an ordinary word from the marker ("before") must not steal the
    // attribution — the exemption belongs to the line the marker actually starts on.
    [`A sentence before anything.
<!-- stale-marker-allow -->
re-derive this before v9.9.9 ships`, false],
    // A multi-line comment above an exemption: blanking must preserve LINE COUNT, or every
    // raw-line lookup below the comment (allow token, excerpt) shifts onto the wrong line.
    [`<!-- an editor
note spanning
three lines -->
<!-- stale-marker-allow -->
re-derive this before v9.9.9 ships`, false],
    // -- must NOT trip: ordinary code, and prose that merely contains a marker substring --
    ['fn tune(x: f64) -> f64 { x }', false],
    ['let y = self.tune(0.5);', false],
    ['let seed = fortune(rng);', false],
    ['fn attune(&self) -> f64 { 0.0 }', false],
    ['`collection_memberships` converge to ONE row', false],
    ['relationships between notes are row-per-edge', false],
    ['the release ships an additive API', false],
    ['let before_the_release_ships = true;', false],  // stripping decoration must not forge a phrase
    ['<td>TUNE</td><td>(x)</td>', false],             // adjacent cells render apart; deleting tags must not join them
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

  // The changelog's SHIPPED sections are immutable history: an entry that accurately recorded a
  // then-provisional value must never block a future release, because the only way to clear it
  // would be rewriting a released entry. Only `[Unreleased]` and the section being cut are asserted
  // by this release, so only those are scanned — pinned here because a string corpus cannot express
  // "which section was this line in".
  const changelog = [
    '# Changelog', '', '## [Unreleased]', '', 'UNRELEASED', '',
    '## [9.9.9] - 2026-01-01', '', 'CUTTING', '',
    '## [9.9.8] - 2025-12-01', '', 'SHIPPED', '',
  ].join('\n');
  const stale = 'the threshold was provisional pending field results';
  const sectionCases = [
    ['SHIPPED', false, 'a shipped section is immutable history'],
    ['UNRELEASED', true, '[Unreleased] is asserted by this release'],
    ['CUTTING', true, 'the section being cut is asserted by this release'],
  ];
  // Driven through scanRepo() on a real temp tree, NOT by calling the masking function directly —
  // otherwise this proves the unit works while a deleted call site would still pass.
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
 * Scan a repository root and return every hit as `{file, line, why, excerpt}`.
 *
 * A function rather than top-level code so `--self-check` can exercise the REAL path against a
 * throwaway tree. Testing `maskReleasedChangelogSections` directly proved the unit worked while
 * saying nothing about whether it was wired in — deleting its call site left the self-check green.
 * That unit-passes-integration-unwired gap is the one this file keeps rediscovering, so the scan is
 * now callable and the wiring is pinned.
 */
export function scanRepo(root, version) {
  const hits = [];
  for (const file of sourceFiles(root)) {
    let text;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      continue; // an optional path (CHANGELOG in a partial checkout) is not this gate's business
    }
    // The changelog is scanned only where the release makes an assertion: `[Unreleased]` and the
    // section being cut. Its shipped sections are immutable history, like `docs/plans`.
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
const failed = found.length;

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
