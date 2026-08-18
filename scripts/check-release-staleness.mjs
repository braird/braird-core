#!/usr/bin/env node
// Fail when finished work has stopped moving toward a device (SUR-1070 follow-up).
//
// THE GAP THIS CLOSES. braird-core ships through two hops, and NOTHING watched either one. A fix
// merges to `main` and sits in `[Unreleased]` until somebody remembers to cut a release; the release
// is tagged and sits published until somebody remembers to bump `braird-core.lock` in the app repos.
// Both hops are deliberate — no floating versions in a crypto core, and the pin PR is the
// integration gate (docs/pinning.md) — but neither had a clock on it. SUR-1070's note-tombstoning
// fix merged, and the only thing that surfaced "this is still not on a phone" was a human asking.
// Every existing gate is a CORRECTNESS gate: it asks whether the tree is consistent, never whether
// consistent work is stuck. `[Unreleased]` reads identically for a typo and for a security fix.
//
// TWO SIGNALS, because there are two ways to stall and neither implies the other:
//   1. UNRELEASED — `[Unreleased]` carries a `### Security` section and no release has taken it.
//   2. UNPINNED — a release exists that a consumer repo's pin still trails.
// A fix that merges but is never released is invisible to (2): with no new tag, every consumer
// agrees with the newest tag and looks current.
//
// SEVERITY DRIVES THE DEADLINE, and that is the whole reason this is usable. A gate that nags about
// every unpinned patch is a gate people mute, and a muted gate is worse than none — the same
// argument `check-stale-release-markers.mjs` makes for staying narrow. So an unpinned range
// containing a `### Security` section is due in 7 days; anything else gets 30. A release nobody
// urgently needs can wait for the next feature pin without anyone hearing about it.
//
// WHAT THIS DOES NOT DO. It does not judge whether a release SHOULD be cut, or open PRs, or block
// a merge — it runs on a schedule, not in the merge path, because "you have not shipped this yet"
// is never a reason to reject the next commit. It reports, loudly, on a clock.
//
// Usage:  node scripts/check-release-staleness.mjs [--consumers <dir>] [--now <ISO>]
//         node scripts/check-release-staleness.mjs --self-check
//
// `--consumers <dir>` holds one shallow clone per consumer, named for the repo (e.g.
// `<dir>/braird-android`). A consumer that is absent is REPORTED, never skipped: a clone that
// failed must not read as "nothing to pin" (a fail-open gate is a decoration).

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const DAY_MS = 86_400_000;

/** Days a stalled hop is allowed before this fails, by whether security work is caught in it. */
const DEADLINE_DAYS = { security: 7, routine: 30 };

/** Every repo that pins braird-core, and where its pinned tag lives. */
const CONSUMERS = [
  { repo: 'braird-android', file: 'gradle/braird-core.lock', tag: /^\s*tag\s*=\s*(v\S+)\s*$/m },
  { repo: 'braird-ios', file: 'braird-core.lock', tag: /^\s*BRAIRD_CORE_TAG\s*=\s*(v\S+)\s*$/m },
];

// ── pure core ─────────────────────────────────────────────────────────────────
// Everything below takes data and returns findings. The git and filesystem reads live at the edges,
// which is what lets `--self-check` drive the real logic instead of a paraphrase of it.

/** Split a Keep a Changelog file into its `[Unreleased]` body and its released sections. */
export function parseChangelog(text) {
  const parts = text.split(/^## \[([^\]]+)\][^\n]*$/m);
  // parts[0] is the preamble; thereafter [heading, body, heading, body, ...].
  const sections = [];
  for (let i = 1; i < parts.length; i += 2) {
    sections.push({ version: parts[i], body: parts[i + 1] ?? '' });
  }
  const unreleased = sections.find((s) => s.version === 'Unreleased')?.body ?? '';
  const released = sections.filter((s) => s.version !== 'Unreleased');
  return { unreleased, released };
}

/** Keep a Changelog puts security work under its own heading. That heading IS the severity signal. */
export function hasSecuritySection(body) {
  return /^### Security\s*$/m.test(body);
}

/** `v1.2.3` / `1.2.3` → [1,2,3]. Anything else → null, so a garbled pin is reported, not ranked. */
export function parseVersion(raw) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(raw ?? '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/** The released sections strictly newer than `pinned` — the range a consumer has not taken yet. */
export function releasesAfter(released, pinned) {
  const from = parseVersion(pinned);
  if (!from) return null;
  return released.filter((s) => {
    const v = parseVersion(s.version);
    return v && compareVersions(v, from) > 0;
  });
}

function ageDays(now, since) {
  return Math.floor((Date.parse(now) - Date.parse(since)) / DAY_MS);
}

/**
 * The whole decision, as one pure function.
 *
 * `unreleasedSecuritySince` is when `### Security` FIRST appeared under `[Unreleased]` — not when
 * the last release was cut. Those differ, and the difference matters: dating the finding from the
 * previous tag would accuse a fix merged this morning of being months late, which is exactly the
 * kind of false alarm that gets a gate switched off.
 */
export function evaluate({ changelog, latestTag, latestTagDate, unreleasedSecuritySince, consumers, now }) {
  const { unreleased, released } = parseChangelog(changelog);
  const findings = [];

  if (hasSecuritySection(unreleased)) {
    const age = unreleasedSecuritySince === null ? null : ageDays(now, unreleasedSecuritySince);
    if (age === null) {
      findings.push({
        signal: 'unreleased',
        detail: 'CHANGELOG [Unreleased] has a ### Security section but its first commit could not be dated',
      });
    } else if (age > DEADLINE_DAYS.security) {
      findings.push({
        signal: 'unreleased',
        detail:
          `security work has sat in CHANGELOG [Unreleased] for ${age} days ` +
          `(limit ${DEADLINE_DAYS.security}) — cut a release, or move the entry if it is not security work`,
      });
    }
  }

  for (const { repo, pinnedTag, error } of consumers) {
    if (error) {
      findings.push({ signal: 'unpinned', detail: `${repo}: pin could not be read (${error})` });
      continue;
    }
    const behind = releasesAfter(released, pinnedTag);
    if (behind === null) {
      findings.push({ signal: 'unpinned', detail: `${repo}: unparseable pinned tag ${JSON.stringify(pinnedTag)}` });
      continue;
    }
    if (behind.length === 0) continue;

    const security = behind.some((s) => hasSecuritySection(s.body));
    const limit = security ? DEADLINE_DAYS.security : DEADLINE_DAYS.routine;
    const age = ageDays(now, latestTagDate);
    if (age > limit) {
      const versions = behind.map((s) => s.version).join(', ');
      findings.push({
        signal: 'unpinned',
        detail:
          `${repo} pins ${pinnedTag}, ${behind.length} release(s) behind ${latestTag} ` +
          `(${versions})${security ? ' — the range contains SECURITY work' : ''}; ` +
          `${latestTag} is ${age} days old (limit ${limit})`,
      });
    }
  }
  return findings;
}

// ── edges: git + filesystem ───────────────────────────────────────────────────

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

function latestReleaseTag() {
  const tags = git('tag', '--list', 'v*', '--sort=-v:refname').split('\n').filter(Boolean);
  if (tags.length === 0) return null;
  return { tag: tags[0], date: git('log', '-1', '--format=%cI', tags[0]) };
}

/**
 * When `### Security` first showed up under `[Unreleased]` after the last release.
 *
 * Walks the commits that touched CHANGELOG.md since the tag, oldest first, and stops at the first
 * one whose `[Unreleased]` already carried the heading. Bounded by the commits in one release
 * window, so it stays cheap. Returns null when nothing since the tag has it — which is also the
 * answer when the section arrived and then left again.
 */
function securityFirstSeenSince(tag) {
  const range = tag ? `${tag}..HEAD` : 'HEAD';
  const shas = git('rev-list', '--reverse', range, '--', 'CHANGELOG.md').split('\n').filter(Boolean);
  for (const sha of shas) {
    let text;
    try {
      text = git('show', `${sha}:CHANGELOG.md`);
    } catch {
      continue; // the file did not exist at that commit
    }
    if (hasSecuritySection(parseChangelog(text).unreleased)) return git('log', '-1', '--format=%cI', sha);
  }
  return null;
}

function readConsumers(dir) {
  return CONSUMERS.map(({ repo, file, tag }) => {
    const path = join(dir, repo, file);
    if (!existsSync(path)) return { repo, error: `${file} not found under ${join(dir, repo)}` };
    const m = tag.exec(readFileSync(path, 'utf8'));
    return m ? { repo, pinnedTag: m[1] } : { repo, error: `no tag line matched in ${file}` };
  });
}

// ── self-check ────────────────────────────────────────────────────────────────
// The corpus is the specification. Each row states a situation and the finding signals it must
// produce, so the boundary between "report" and "stay quiet" is executable rather than folklore.

const SEC = '## [Unreleased]\n\n### Security\n- a fix\n\n## [1.2.0] - 2026-01-01\n\n### Security\n- shipped\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n';
// A SHIPPED security release: the heading sits in the released section, not in `[Unreleased]`. This
// is what the unpinned signal must react to, and keeping it separate from SEC is what stops the two
// signals being tested as one.
const SEC_RELEASED = '## [Unreleased]\n\n### Fixed\n- a typo\n\n## [1.2.0] - 2026-01-01\n\n### Security\n- shipped\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n';
const QUIET = '## [Unreleased]\n\n### Fixed\n- a typo\n\n## [1.2.0] - 2026-01-01\n\n### Added\n- feature\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n';

const CORPUS = [
  {
    name: 'security sitting unreleased past the deadline is reported',
    input: { changelog: SEC, unreleasedSecuritySince: '2026-02-01T00:00:00Z', now: '2026-02-20T00:00:00Z' },
    expect: ['unreleased'],
  },
  {
    name: 'security merged inside the grace period is NOT reported — dated from the entry, not the tag',
    input: { changelog: SEC, unreleasedSecuritySince: '2026-02-19T00:00:00Z', now: '2026-02-20T00:00:00Z' },
    expect: [],
  },
  {
    name: 'a non-security [Unreleased] is never a staleness finding, however old',
    input: { changelog: QUIET, unreleasedSecuritySince: null, now: '2027-01-01T00:00:00Z' },
    expect: [],
  },
  {
    name: 'a consumer trailing a SECURITY release is reported after 7 days',
    input: {
      changelog: SEC_RELEASED,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', pinnedTag: 'v1.1.0' }],
      latestTagDate: '2026-01-01T00:00:00Z',
      now: '2026-01-15T00:00:00Z',
    },
    expect: ['unpinned'],
  },
  {
    name: 'a consumer trailing a ROUTINE release is quiet at 14 days and reported at 45',
    input: {
      changelog: QUIET,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', pinnedTag: 'v1.1.0' }],
      latestTagDate: '2026-01-01T00:00:00Z',
      now: '2026-01-15T00:00:00Z',
    },
    expect: [],
  },
  {
    name: 'the same routine lag IS reported once it passes 30 days',
    input: {
      changelog: QUIET,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', pinnedTag: 'v1.1.0' }],
      latestTagDate: '2026-01-01T00:00:00Z',
      now: '2026-02-15T00:00:00Z',
    },
    expect: ['unpinned'],
  },
  {
    name: 'a current consumer is quiet',
    input: {
      changelog: QUIET,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', pinnedTag: 'v1.2.0' }],
      latestTagDate: '2026-01-01T00:00:00Z',
      now: '2027-01-01T00:00:00Z',
    },
    expect: [],
  },
  {
    name: 'an unreadable consumer pin FAILS rather than passing silently',
    input: {
      changelog: QUIET,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', error: 'clone missing' }],
      now: '2026-01-15T00:00:00Z',
    },
    expect: ['unpinned'],
  },
  {
    name: 'a garbled pinned tag is reported, never ranked as current',
    input: {
      changelog: QUIET,
      unreleasedSecuritySince: null,
      consumers: [{ repo: 'app', pinnedTag: 'latest' }],
      latestTagDate: '2026-01-01T00:00:00Z',
      now: '2026-01-15T00:00:00Z',
    },
    expect: ['unpinned'],
  },
];

function selfCheck() {
  let failed = 0;
  for (const { name, input, expect } of CORPUS) {
    const got = evaluate({
      latestTag: 'v1.2.0',
      latestTagDate: '2026-01-01T00:00:00Z',
      consumers: [],
      ...input,
    }).map((f) => f.signal);
    const ok = got.length === expect.length && got.every((s, i) => s === expect[i]);
    if (!ok) {
      failed += 1;
      console.error(`  FAIL ${name}\n       expected [${expect}] got [${got}]`);
    }
  }
  if (failed > 0) {
    console.error(`check-release-staleness: self-check FAILED (${failed}/${CORPUS.length})`);
    process.exit(1);
  }
  console.log(`check-release-staleness: self-check OK (${CORPUS.length} cases)`);
}

// ── entry ─────────────────────────────────────────────────────────────────────

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-check')) return selfCheck();

  const at = (flag) => {
    const i = argv.indexOf(flag);
    return i === -1 ? null : argv[i + 1];
  };
  const now = at('--now') ?? new Date().toISOString();
  const consumersDir = at('--consumers');

  const latest = latestReleaseTag();
  if (!latest) {
    console.error('check-release-staleness: no v* tag found — nothing to measure against');
    process.exit(2);
  }

  const findings = evaluate({
    changelog: readFileSync('CHANGELOG.md', 'utf8'),
    latestTag: latest.tag,
    latestTagDate: latest.date,
    unreleasedSecuritySince: securityFirstSeenSince(latest.tag),
    consumers: consumersDir ? readConsumers(consumersDir) : [],
    now,
  });

  if (findings.length === 0) {
    console.log(`check-release-staleness: OK — nothing is stuck (latest ${latest.tag})`);
    return;
  }
  console.error(`check-release-staleness: ${findings.length} finding(s)\n`);
  for (const f of findings) console.error(`  [${f.signal}] ${f.detail}`);
  console.error('\nEach finding names work that is FINISHED but not on a device. Cut the release, or');
  console.error('open the pin PR (docs/pinning.md). Neither hop is automatic, by design.');
  process.exit(1);
}

main();
