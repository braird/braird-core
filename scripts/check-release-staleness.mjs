#!/usr/bin/env node
// Fail when finished work has stopped moving toward a device (SUR-1070 follow-up).
//
// THE GAP THIS CLOSES. braird-core ships through two hops, and NOTHING watched either one. A fix
// merges to `main` and sits in `[Unreleased]` until somebody remembers to cut a release; the release
// is published and sits there until somebody remembers to bump `braird-core.lock` in the app repos.
// Both hops are deliberate — no floating versions in a crypto core, and the pin PR is the
// integration gate (docs/pinning.md) — but neither had a clock on it. SUR-1070's note-tombstoning
// fix merged, was released, and the only thing that surfaced "this is still not on a phone" was a
// human asking. Every existing gate is a CORRECTNESS gate: it asks whether the tree is consistent,
// never whether consistent work is stuck. `[Unreleased]` reads identically for a typo and for a
// security fix.
//
// THREE SIGNALS, because there are three places work stops and none implies the others:
//   1. UNRELEASED  — `[Unreleased]` carries `### Security` and no release has taken it.
//   2. UNPUBLISHED — a CHANGELOG section names a version with no consumable GitHub Release.
//   3. UNPINNED    — a published release a consumer's pin still trails.
// A fix that merges but is never released is invisible to (3): with no new release, every consumer
// agrees with the newest one and looks current. And (2) is not decoration — `release.yml` publishes
// create-only at the END of the job DAG, so a tag whose build failed leaves a tag with no release
// behind it. Without (2) that tag silently ends signal (1) (the entries left `[Unreleased]`) while
// signal (3) starts telling consumers to pin something they cannot fetch.
//
// A TAG IS NOT A RELEASE, and this checker never treats one as the other. Every judgement here is
// made against the published GitHub Releases passed in via `--releases`, never against `git tag`.
//
// SEVERITY DRIVES THE DEADLINE, and that is the whole reason this is usable. A gate that nags about
// every unpinned patch is a gate people mute, and a muted gate is worse than none — the same
// argument `check-stale-release-markers.mjs` makes for staying narrow. A stalled range containing a
// `### Security` section is due in 7 days; anything else gets 30.
//
// THE DEADLINE RUNS FROM THE OLDEST STALLED RELEASE, NEVER THE NEWEST. Dating a consumer's lag from
// the newest release would let an active repo suppress its own alarm forever: each new tag resets
// the clock to zero while an old security release stays unpinned underneath. The age therefore comes
// from the OLDEST unpinned release in the range — and, when the range contains security work, from
// the oldest unpinned SECURITY release specifically, since that is the one whose deadline is short.
//
// WHAT THIS DOES NOT DO. It does not judge whether a release SHOULD be cut, or open PRs, or block a
// merge — it runs on a schedule, not in the merge path, because "you have not shipped this yet" is
// never a reason to reject the next commit. It reports, loudly, on a clock.
//
// Usage:  node scripts/check-release-staleness.mjs --releases <file> [--consumers <dir>] [--now ISO]
//         node scripts/check-release-staleness.mjs --self-check
//
// `--releases <file>` is the JSON body of `gh api repos/braird/braird-core/releases`. Required, not
// optional: without it this cannot tell a published release from a bare tag, and guessing would
// reintroduce exactly the failure mode signal (2) exists to catch.
// `--consumers <dir>` holds one shallow clone per consumer, named for the repo. A consumer that is
// absent is REPORTED, never skipped: a clone that failed must not read as "nothing to pin".

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DAY_MS = 86_400_000;

/**
 * The one asset every release has carried, across all 27 of them. It is the checksum manifest the
 * whole pinning contract rests on, so a release without it is not pinnable and not a release.
 */
const MANIFEST_ASSET = 'SHA256SUMS.txt';

/**
 * Days a stalled hop is allowed before this fails, by whether security work is caught in it.
 *
 * Compared with `>=`, not `>`. `ageDays` floors, so a strict comparison quietly bought an extra day:
 * work stalled 7 days 23 hours read as `age === 7` and stayed silent, and on a daily schedule that
 * pushed a 7-day deadline out to nearly 9. A deadline the code does not enforce on the day it
 * advertises is a deadline nobody can rely on.
 */
const DEADLINE_DAYS = { security: 7, routine: 30 };

/**
 * Every repo that pins braird-core, where its pinned tag lives, and the assets it needs to exist.
 *
 * `assets` is a FUNCTION OF THE VERSION, not a set of extension patterns. Release artifacts carry
 * the version in the filename (`braird-core-0.15.1.aar`), so an extension match would accept a
 * `v1.2.0` release that only contains a stale `braird-core-1.1.0.aar` — the checker would then tell
 * a consumer to pin a version whose downloads do not exist. `BrairdCore.swift` is genuinely
 * unversioned and is listed literally.
 */
const CONSUMERS = [
  {
    repo: 'braird-android',
    file: 'gradle/braird-core.lock',
    tag: /^\s*tag\s*=\s*(v\S+)\s*$/m,
    assets: (v) => [`braird-core-${v}.aar`, `braird-core-desktop-${v}.jar`],
  },
  {
    repo: 'braird-ios',
    file: 'braird-core.lock',
    tag: /^\s*BRAIRD_CORE_TAG\s*=\s*(v\S+)\s*$/m,
    assets: (v) => [`braird-core-${v}.xcframework.zip`, 'BrairdCore.swift'],
  },
];

// ── pure core ─────────────────────────────────────────────────────────────────
// Everything below takes data and returns findings. The git, filesystem and API reads live at the
// edges, which is what lets `--self-check` drive the real logic instead of a paraphrase of it.

/**
 * Split a Keep a Changelog file into its `[Unreleased]` body and its released sections.
 *
 * The heading's date tail is kept, not discarded: it is the only thing that can date a section whose
 * release was never published, which is precisely the case signal (2) has to age.
 */
export function parseChangelog(text) {
  const parts = text.split(/^## \[([^\]]+)\]([^\n]*)$/m);
  // parts[0] is the preamble; thereafter [version, headingTail, body, version, headingTail, ...].
  const sections = [];
  for (let i = 1; i < parts.length; i += 3) {
    const date = /-\s*(\d{4}-\d{2}-\d{2})/.exec(parts[i + 1] ?? '')?.[1] ?? null;
    sections.push({ version: parts[i], date, body: parts[i + 2] ?? '' });
  }
  return {
    unreleased: sections.find((s) => s.version === 'Unreleased')?.body ?? '',
    released: sections.filter((s) => s.version !== 'Unreleased'),
  };
}

/** Keep a Changelog puts security work under its own heading. That heading IS the severity signal. */
export function hasSecuritySection(body) {
  return /^### Security\s*$/m.test(body);
}

/**
 * `v1.2.3`, `1.2.3`, `v1.2.3-rc1`, `v1.2.3.4` → `{ core, pre }`; anything else → null, so a garbled
 * pin is reported rather than silently ranked.
 *
 * The suffix is KEPT. `release.yml` accepts `^v\d+\.\d+\.\d+([.-][0-9A-Za-z.]+)?$` — prerelease tags
 * are a supported shape — and a parser that dropped the suffix would rank `v1.2.3-rc1` equal to
 * `v1.2.3`, so a consumer stuck on the release candidate would read as current forever.
 */
export function parseVersion(raw) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:[.-]([0-9A-Za-z.]+))?$/.exec(String(raw ?? '').trim());
  return m ? { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null } : null;
}

/** Digit runs compare numerically, so `rc9` sorts before `rc10` rather than after it. */
function compareNatural(a, b) {
  const chunk = (s) => s.match(/\d+|\D+/g) ?? [];
  const [x, y] = [chunk(a), chunk(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const [p, q] = [x[i], y[i]];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const both = /^\d+$/.test(p) && /^\d+$/.test(q);
    const cmp = both ? Number(p) - Number(q) : p < q ? -1 : p > q ? 1 : 0;
    if (cmp !== 0) return cmp < 0 ? -1 : 1;
  }
  return 0;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i += 1) if (a.core[i] !== b.core[i]) return a.core[i] < b.core[i] ? -1 : 1;
  if (a.pre === b.pre) return 0;
  // A finished release outranks any suffixed build of the same core version.
  if (a.pre === null) return 1;
  if (b.pre === null) return -1;
  return compareNatural(a.pre, b.pre);
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

/**
 * Age in whole days, or null when either end is unparseable.
 *
 * Returning null rather than NaN is the point. `NaN > limit` is FALSE, so an invalid timestamp used
 * to make every deadline pass forever — a date typo silently disabled the signal it was feeding.
 * `release.yml` only checks a CHANGELOG date's SHAPE (`[0-9]{4}-[0-9]{2}-[0-9]{2}`), so `2026-13-01`
 * reaches this function in the ordinary course of a typo, not only under attack.
 */
/**
 * `YYYY-MM-DD` -> an ISO instant, or null when it is not a real calendar date.
 *
 * `Date.parse` is not a validator and review was right to say so: `2026-13-01` is NaN, but
 * `2026-02-30` NORMALISES to 2026-03-02 and `2025-02-29` to 2025-03-01. A day-overflow typo would
 * therefore silently shift a deadline instead of being reported. `release.yml` checks only the SHAPE
 * of this field, so both kinds arrive by ordinary typo. The components have to round-trip.
 */
export function parseCalendarDate(ymd) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(ymd ?? ''));
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(Date.UTC(y, mo - 1, d));
  const roundTrips = at.getUTCFullYear() === y && at.getUTCMonth() + 1 === mo && at.getUTCDate() === d;
  return roundTrips ? at.toISOString() : null;
}

function ageDays(now, since) {
  const [a, b] = [Date.parse(now), Date.parse(since)];
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.floor((a - b) / DAY_MS);
}

/** Oldest first, so "the one whose clock started earliest" is just `[0]`. */
function oldestFirst(sections) {
  return [...sections].sort((a, b) => compareVersions(parseVersion(a.version), parseVersion(b.version)));
}

/**
 * The whole decision, as one pure function.
 *
 * `published` maps a version string to its release's `published_at`. A version absent from it has no
 * consumable release, whatever `git tag` says.
 *
 * `unreleasedSecuritySince` is when `### Security` FIRST appeared under `[Unreleased]` — not when the
 * last release was cut. Those differ, and the difference matters: dating the finding from the
 * previous release would accuse a fix merged this morning of being months late, which is exactly the
 * kind of false alarm that gets a gate switched off.
 */
export function evaluate({ changelog, published, unreleasedSecuritySince, consumers, now }) {
  const { unreleased, released } = parseChangelog(changelog);
  const findings = [];
  const add = (signal, detail) => findings.push({ signal, detail });

  // (1) UNRELEASED — security work that no release has taken.
  if (hasSecuritySection(unreleased)) {
    if (unreleasedSecuritySince === null) {
      add('unreleased', 'CHANGELOG [Unreleased] has a ### Security section but its first commit could not be dated');
    } else {
      const age = ageDays(now, unreleasedSecuritySince);
      if (age === null) {
        add('unreleased', `CHANGELOG [Unreleased] has a ### Security section dated unparseably (${unreleasedSecuritySince})`);
      } else if (age >= DEADLINE_DAYS.security) {
        add(
          'unreleased',
          `security work has sat in CHANGELOG [Unreleased] for ${age} days (limit ` +
            `${DEADLINE_DAYS.security}) — cut a release, or move the entry if it is not security work`,
        );
      }
    }
  }

  // (2) UNPUBLISHED — the CHANGELOG claims a release consumers cannot fetch. `release.yml` publishes
  // create-only at the end of its DAG, so a failed build leaves the tag with no release behind it.
  // Aged from the section's own heading date: during a release PR the section legitimately exists
  // before the tag is pushed, and a signal that fired there would fire on every release.
  for (const s of oldestFirst(released)) {
    if (published.has(s.version)) continue;
    if (!s.date) {
      add('unpublished', `CHANGELOG section [${s.version}] has no published release and no date to age it by`);
      continue;
    }
    const limit = hasSecuritySection(s.body) ? DEADLINE_DAYS.security : DEADLINE_DAYS.routine;
    const age = ageDays(now, parseCalendarDate(s.date));
    if (age === null) {
      add(
        'unpublished',
        `CHANGELOG section [${s.version}] has no published release and its date ${s.date} is not a real ` +
          'date — release.yml checks the SHAPE of this field, not its validity, so a typo here would ' +
          'otherwise disable this signal silently',
      );
    } else if (age >= limit) {
      add(
        'unpublished',
        `CHANGELOG section [${s.version}] (${s.date}, ${age} days old, limit ${limit}) has NO published ` +
          `release${hasSecuritySection(s.body) ? ' and contains SECURITY work' : ''} — a tag whose ` +
          'release build failed leaves exactly this state; re-run the release or cut a new version',
      );
    }
  }

  // (3) UNPINNED — a consumer trailing a published release.
  for (const { repo, pinnedTag, error, assets } of consumers) {
    if (error) {
      add('unpinned', `${repo}: pin could not be read (${error})`);
      continue;
    }
    // A pin must name a release that EXISTS before its lag means anything. `v9.9.9` — a typo, or a
    // pin written ahead of the release it expects — parses fine and sorts above every section, so
    // `behind` comes back empty and the consumer reads as perfectly current forever. Silence is the
    // one answer this checker must never give by accident.
    if (!published.has(String(pinnedTag).replace(/^v/, ''))) {
      add('unpinned', `${repo}: pins ${pinnedTag}, which is not a published release — it cannot be fetched`);
      continue;
    }
    const behind = releasesAfter(released, pinnedTag);
    if (behind === null) {
      add('unpinned', `${repo}: unparseable pinned tag ${JSON.stringify(pinnedTag)}`);
      continue;
    }
    // Only a release a consumer could actually take counts against it.
    // A release only counts against a consumer if it actually carries THAT consumer's artifacts.
    // A partial upload, or an asset deleted after the fact, must not become "you are behind, go pin
    // this" for a release with no AAR or no xcframework in it.
    const incomplete = [];
    const fetchable = oldestFirst(
      behind.filter((s) => {
        const rel = published.get(s.version);
        if (!rel) return false;
        const required = typeof assets === 'function' ? assets(s.version) : [];
        const missing = required.filter((name) => !rel.assets.includes(name));
        if (missing.length === 0) return true;
        incomplete.push(`${s.version} (no asset matching ${missing.join(', ')})`);
        return false;
      }),
    );
    // Reported, never silently dropped - an incomplete release is a broken release, and staying
    // quiet about it is how the publication hole worked in the first place.
    if (incomplete.length > 0) {
      add('unpublished', `${repo} cannot pin ${incomplete.join('; ')} - the release is published but incomplete`);
    }
    if (fetchable.length === 0) continue;

    // The clock starts at the OLDEST stalled release, never the newest — otherwise every new tag
    // resets it to zero and an old security release underneath is suppressed indefinitely. When the
    // range contains security work, the oldest SECURITY release is the one that sets the deadline.
    const securities = fetchable.filter((s) => hasSecuritySection(s.body));
    const clock = securities[0] ?? fetchable[0];
    const limit = securities.length > 0 ? DEADLINE_DAYS.security : DEADLINE_DAYS.routine;
    const age = ageDays(now, published.get(clock.version).publishedAt);
    if (age === null) {
      add('unpinned', `${repo}: release ${clock.version} has an unparseable published_at`);
      continue;
    }
    if (age >= limit) {
      add(
        'unpinned',
        `${repo} pins ${pinnedTag}, ${fetchable.length} release(s) behind ` +
          `(${fetchable.map((s) => s.version).join(', ')})${securities.length > 0 ? ' — the range contains SECURITY work' : ''}; ` +
          `the oldest unpinned${securities.length > 0 ? ' security' : ''} release ${clock.version} ` +
          `published ${age} days ago (limit ${limit})`,
      );
    }
  }
  return findings;
}

// ── edges: git, filesystem, release list ──────────────────────────────────────

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

/**
 * version → `{ publishedAt, assets }`, for releases that are a release at all.
 *
 * A draft is not one. Neither is a release without `SHA256SUMS.txt`: that manifest is what makes a
 * release checksum-pinnable, which is the entire pinning contract (docs/pinning.md), and
 * `release.yml` writes it in the same create-only step as the payloads — so its absence means that
 * step did not finish.
 *
 * **Deliberately not "has all seven named assets", which review proposed and the history refutes.**
 * The published set is 3, 5 and 7 assets across 27 releases: it GREW as the product did, with the
 * iOS xcframework and wrapper arriving at SUR-745. Requiring today's seven would mark nine
 * historical releases unpublished — false, since each was complete for its time, and a flood of
 * findings is how a gate gets muted. Completeness is instead judged PER CONSUMER, against the
 * artifacts that consumer actually pins ([`CONSUMERS`]), which is both the real question ("is there
 * an AAR in there for me?") and self-maintaining as the set changes again.
 */
export function publishedReleases(json) {
  const map = new Map();
  for (const r of json) {
    if (r.draft) continue;
    const names = Array.isArray(r.assets) ? r.assets.map((a) => a.name) : [];
    if (!names.includes(MANIFEST_ASSET)) continue;
    const v = parseVersion(r.tag_name);
    if (v) map.set(String(r.tag_name).replace(/^v/, ''), { publishedAt: r.published_at, assets: names });
  }
  return map;
}

/** The newest published release, by version precedence rather than by publish order. */
function newestPublished(published) {
  let best = null;
  for (const version of published.keys()) {
    const v = parseVersion(version);
    if (v && (best === null || compareVersions(v, parseVersion(best)) > 0)) best = version;
  }
  return best;
}

/**
 * When the `### Security` heading CURRENTLY under `[Unreleased]` got there — the start of the
 * unbroken run of commits carrying it, NOT the first time one ever did.
 *
 * That distinction is the whole function. A heading can be added, then removed or reclassified, then
 * added again by UNRELATED work before any release intervenes. Returning the first historical
 * sighting would hand the new fix the old one's age and fail it on arrival — and a gate that
 * accuses you of being late on the day you commit is a gate that gets switched off. So this finds
 * the most recent absent→present transition: walk the range oldest first, reset on every commit
 * WITHOUT the heading, and date from the first commit of the run that survives to HEAD.
 *
 * Bounded by one release window, so reading every commit's CHANGELOG in the range stays cheap.
 * Returns null when no commit in the range carries it, and when the range cannot be walked at all.
 */
function securityFirstSeenSince(tag) {
  const range = tag ? `${tag}..HEAD` : 'HEAD';
  let shas;
  try {
    shas = git('rev-list', '--reverse', range, '--', 'CHANGELOG.md').split('\n').filter(Boolean);
  } catch {
    return null; // the tag is not present locally (shallow clone) — reported by the caller's grace
  }
  let runStart = null; // first commit of the CURRENT unbroken run of commits carrying the heading
  for (const sha of shas) {
    let present;
    try {
      present = hasSecuritySection(parseChangelog(git('show', `${sha}:CHANGELOG.md`)).unreleased);
    } catch {
      continue; // the file did not exist at that commit — neither present nor a break
    }
    if (present) {
      if (runStart === null) runStart = sha;
    } else {
      runStart = null; // the heading went away: any later one starts a NEW interval
    }
  }
  return runStart === null ? null : git('log', '-1', '--format=%cI', runStart);
}

/**
 * One `CONSUMERS` entry plus the contents of its pin file (or null when it could not be read) → the
 * shape [`evaluate`] consumes.
 *
 * **Everything except the reading instructions is carried through by spread, deliberately.** An
 * earlier version destructured `{ repo, file, tag }` and rebuilt the result field by field, which
 * silently dropped `assets` — so the per-consumer completeness rule was dead in production while the
 * corpus, whose fixtures build consumer objects by hand, went on passing. Spreading means a field
 * added to `CONSUMERS` reaches `evaluate` without anyone remembering this function exists.
 *
 * Split out of the filesystem walk so the corpus can assert that, which is the only way to test a
 * seam whose whole failure mode is losing a field between two halves that each work.
 */
export function consumerFromFile(config, contents) {
  const { file, tag, ...carried } = config; // `carried` is repo + assets + anything added later
  if (contents === null) return { ...carried, error: `${file} could not be read` };
  const m = tag.exec(contents);
  return m ? { ...carried, pinnedTag: m[1] } : { ...carried, error: `no tag line matched in ${file}` };
}

function readConsumers(dir) {
  return CONSUMERS.map((config) => {
    const path = join(dir, config.repo, config.file);
    return consumerFromFile(config, existsSync(path) ? readFileSync(path, 'utf8') : null);
  });
}

// ── self-check ────────────────────────────────────────────────────────────────
// The corpus is the specification. Each row states a situation and the finding signals it must
// produce, so the boundary between "report" and "stay quiet" is executable rather than folklore.

const CL = {
  // `### Security` still sitting in [Unreleased].
  unreleasedSecurity:
    '## [Unreleased]\n\n### Security\n- a fix\n\n## [1.2.0] - 2026-01-01\n\n### Added\n- x\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n',
  // A SHIPPED security release: the heading is in the released section, not in [Unreleased]. Keeping
  // this separate is what stops signals (1) and (3) being tested as one.
  shippedSecurity:
    '## [Unreleased]\n\n### Fixed\n- a typo\n\n## [1.2.0] - 2026-01-01\n\n### Security\n- shipped\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n',
  quiet:
    '## [Unreleased]\n\n### Fixed\n- a typo\n\n## [1.2.0] - 2026-01-01\n\n### Added\n- feature\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n',
  // The P1 shape: an old SECURITY release the consumer never took, with a routine release on top.
  securityThenRoutine:
    '## [Unreleased]\n\n### Fixed\n- x\n\n## [1.3.0] - 2026-05-01\n\n### Added\n- routine\n\n## [1.2.0] - 2026-01-20\n\n### Security\n- never pinned\n\n## [1.1.0] - 2025-12-01\n\n### Added\n- x\n',
};

/** A complete release: the manifest plus every artifact both consumers pin. */
/** A complete release: the manifest plus the consumer artifact, named for ITS OWN version. */
const full = (version) => ['SHA256SUMS.txt', `app-${version}.bin`];
const rel = (version, publishedAt, assets = full(version)) => ({ publishedAt, assets });
/** The fixture consumer, declaring its requirement the same way the real ones do. */
const APP = { repo: 'app', assets: (v) => [`app-${v}.bin`] };

const PUB = new Map([
  ['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')],
  ['1.2.0', rel('1.2.0', '2026-01-01T00:00:00Z')],
]);
const PUB_P1 = new Map([
  ['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')],
  ['1.2.0', rel('1.2.0', '2026-01-20T00:00:00Z')],
  ['1.3.0', rel('1.3.0', '2026-05-01T00:00:00Z')],
]);

const CORPUS = [
  {
    name: 'security sitting unreleased past the deadline is reported',
    input: { changelog: CL.unreleasedSecurity, unreleasedSecuritySince: '2026-02-01T00:00:00Z', now: '2026-02-20T00:00:00Z' },
    expect: ['unreleased'],
  },
  {
    name: 'security merged inside the grace period is NOT reported — dated from the entry, not the release',
    input: { changelog: CL.unreleasedSecurity, unreleasedSecuritySince: '2026-02-19T00:00:00Z', now: '2026-02-20T00:00:00Z' },
    expect: [],
  },
  {
    name: 'a non-security [Unreleased] is never a staleness finding, however old',
    input: { changelog: CL.quiet, now: '2027-01-01T00:00:00Z' },
    expect: [],
  },
  {
    name: 'a consumer trailing a SECURITY release is reported after 7 days',
    input: { changelog: CL.shippedSecurity, consumers: [{ ...APP, pinnedTag: 'v1.1.0' }], now: '2026-01-15T00:00:00Z' },
    expect: ['unpinned'],
  },
  {
    name: 'a consumer trailing a ROUTINE release is quiet at 14 days',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'v1.1.0' }], now: '2026-01-15T00:00:00Z' },
    expect: [],
  },
  {
    name: 'the same routine lag IS reported once it passes 30 days',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'v1.1.0' }], now: '2026-02-15T00:00:00Z' },
    expect: ['unpinned'],
  },
  {
    name: 'a current consumer is quiet',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'v1.2.0' }], now: '2027-01-01T00:00:00Z' },
    expect: [],
  },
  {
    name: 'an unreadable consumer pin FAILS rather than passing silently',
    input: { changelog: CL.quiet, consumers: [{ ...APP, error: 'clone missing' }], now: '2026-01-15T00:00:00Z' },
    expect: ['unpinned'],
  },
  {
    name: 'a garbled pinned tag is reported, never ranked as current',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'latest' }], now: '2026-01-15T00:00:00Z' },
    expect: ['unpinned'],
  },
  // ── the deadline runs from the OLDEST stalled release (Codex P1 on PR #93) ──
  {
    name: 'a NEW routine release does not reset the clock on an old unpinned SECURITY release',
    input: {
      changelog: CL.securityThenRoutine,
      published: PUB_P1,
      consumers: [{ ...APP, pinnedTag: 'v1.1.0' }],
      now: '2026-05-01T00:00:00Z', // 1.3.0 published TODAY; 1.2.0 security is 101 days old
    },
    expect: ['unpinned'],
  },
  {
    name: 'and the finding names the oldest SECURITY release as the clock, not the newest release',
    input: {
      changelog: CL.securityThenRoutine,
      published: PUB_P1,
      consumers: [{ ...APP, pinnedTag: 'v1.1.0' }],
      now: '2026-05-01T00:00:00Z',
    },
    detail: /oldest unpinned security release 1\.2\.0 published 101 days ago/,
  },
  // ── a tag is not a release (Codex P2 on PR #93) ──
  {
    name: 'a CHANGELOG section with no published release is reported once it ages past the limit',
    input: { changelog: CL.quiet, published: new Map([['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')]]), now: '2026-03-01T00:00:00Z' },
    expect: ['unpublished'],
  },
  {
    name: 'a section awaiting its tag during a release PR is NOT reported inside the grace period',
    input: { changelog: CL.quiet, published: new Map([['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')]]), now: '2026-01-10T00:00:00Z' },
    expect: [],
  },
  {
    name: 'an unpublished SECURITY section takes the SHORT deadline',
    input: { changelog: CL.shippedSecurity, published: new Map([['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')]]), now: '2026-01-15T00:00:00Z' },
    expect: ['unpublished'],
  },
  {
    name: 'a consumer is never told to pin a version that has no published release',
    input: {
      changelog: CL.quiet,
      published: new Map([['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')]]), // 1.2.0 tagged but never published
      consumers: [{ ...APP, pinnedTag: 'v1.1.0' }],
      now: '2026-01-15T00:00:00Z',
    },
    expect: [], // quiet on the pin; the unpublished signal owns this state (and is inside its grace)
  },
  // ── an unparseable date is a FINDING, never a silent pass (Codex P2 on PR #93) ──
  // `NaN > limit` is false, so before this an invalid date disabled the signal it was feeding — and
  // release.yml validates only the SHAPE of a CHANGELOG date, so `2026-13-01` gets there by typo.
  {
    name: 'an invalid date on an unpublished section is REPORTED, not aged to NaN and ignored',
    input: {
      changelog: '## [Unreleased]\n\n### Fixed\n- x\n\n## [1.2.0] - 2026-13-01\n\n### Added\n- x\n',
      published: new Map(),
      now: '2027-01-01T00:00:00Z',
    },
    detail: /is not a real date/,
  },
  {
    name: 'an invalid unreleased-security date is REPORTED rather than passing every deadline',
    input: {
      changelog: CL.unreleasedSecurity,
      unreleasedSecuritySince: 'not-a-date',
      now: '2027-01-01T00:00:00Z',
    },
    expect: ['unreleased'],
  },
  // ── a normalising calendar date is still an invalid one (Codex P2, second round) ──
  // `Date.parse` is not a validator: 2026-13-01 is NaN, but 2026-02-30 silently becomes 2026-03-02.
  {
    name: 'a day-overflow date that Date.parse NORMALISES is reported, not quietly shifted',
    input: {
      changelog: '## [Unreleased]\n\n### Fixed\n- x\n\n## [1.2.0] - 2026-02-30\n\n### Added\n- x\n',
      published: new Map(),
      now: '2027-01-01T00:00:00Z',
    },
    detail: /is not a real date/,
  },
  // ── a release must carry the artifacts the consumer pins (Codex P2, second round) ──
  {
    name: 'a consumer is never told to pin a release that has no artifact for it',
    input: {
      changelog: CL.quiet,
      published: new Map([['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')], ['1.2.0', rel('1.2.0', '2026-01-01T00:00:00Z', ['SHA256SUMS.txt'])]]),
      consumers: [{ ...APP, pinnedTag: 'v1.1.0' }],
      now: '2026-06-01T00:00:00Z', // long past the routine deadline
    },
    detail: /published but incomplete/,
  },
  // ── the advertised deadline fires ON the advertised day (Codex P2, third round) ──
  // `ageDays` floors, so a strict `>` bought a silent extra day: 7d23h read as 7 and stayed quiet.
  {
    name: 'a security lag of exactly 7 days fires — the deadline is the deadline',
    input: { changelog: CL.shippedSecurity, consumers: [{ ...APP, pinnedTag: 'v1.1.0' }], now: '2026-01-08T00:00:00Z' },
    expect: ['unpinned'],
  },
  {
    name: 'and 6 days 23 hours is still inside it',
    input: { changelog: CL.shippedSecurity, consumers: [{ ...APP, pinnedTag: 'v1.1.0' }], now: '2026-01-07T23:00:00Z' },
    expect: [],
  },
  // ── an artifact must be named for the release it ships in (Codex P2, third round) ──
  {
    name: 'a release carrying only the PREVIOUS version of the artifact is not pinnable',
    input: {
      changelog: CL.quiet,
      published: new Map([
        ['1.1.0', rel('1.1.0', '2025-12-01T00:00:00Z')],
        // Right extension, wrong version — the v1.2.0 download does not exist.
        ['1.2.0', rel('1.2.0', '2026-01-01T00:00:00Z', ['SHA256SUMS.txt', 'app-1.1.0.bin'])],
      ]),
      consumers: [{ ...APP, pinnedTag: 'v1.1.0' }],
      now: '2026-06-01T00:00:00Z',
    },
    detail: /published but incomplete/,
  },
  // ── a pin must name a release that exists (Codex P2, fourth round) ──
  {
    name: 'a pin to a nonexistent release is reported, not treated as ahead of everything',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'v9.9.9' }], now: '2030-01-01T00:00:00Z' },
    expect: ['unpinned'],
  },
  {
    name: 'and the message says why, rather than reporting a lag it cannot compute',
    input: { changelog: CL.quiet, consumers: [{ ...APP, pinnedTag: 'v9.9.9' }], now: '2030-01-01T00:00:00Z' },
    detail: /not a published release/,
  },
  // ── prerelease precedence (Codex P2 on PR #93) ──
  {
    name: 'a consumer stuck on a release candidate is NOT counted as current once the release ships',
    input: {
      changelog: '## [Unreleased]\n\n### Fixed\n- x\n\n## [1.2.0] - 2026-01-01\n\n### Security\n- shipped\n',
      published: new Map([['1.2.0', rel('1.2.0', '2026-01-01T00:00:00Z')]]),
      consumers: [{ ...APP, pinnedTag: 'v1.2.0-rc1' }],
      now: '2026-01-15T00:00:00Z',
    },
    expect: ['unpinned'],
  },
];

/**
 * The corpus drives `evaluate` with hand-built consumer objects, so it can never notice the real
 * `CONSUMERS` config losing a field on its way there. These assertions cover exactly that seam:
 * every declared requirement must survive `consumerFromFile`, whatever the pin file said.
 */
function checkConsumerPlumbing() {
  const problems = [];
  for (const config of CONSUMERS) {
    const cases = [
      ['a pin it could read', consumerFromFile(config, `tag = v1.0.0\nBRAIRD_CORE_TAG=v1.0.0\n`)],
      ['a pin it could not read', consumerFromFile(config, null)],
      ['a pin with no tag line', consumerFromFile(config, 'nothing useful here')],
    ];
    for (const [what, got] of cases) {
      if (got.repo !== config.repo) problems.push(`${config.repo}: ${what} lost \`repo\``);
      if (typeof got.assets !== 'function' || got.assets('9.9.9').length !== config.assets('9.9.9').length) {
        problems.push(`${config.repo}: ${what} lost \`assets\` — the completeness rule would be dead in production`);
      }
    }
  }
  return problems;
}

function selfCheck() {
  let failed = 0;
  for (const problem of checkConsumerPlumbing()) {
    failed += 1;
    console.error(`  FAIL consumer plumbing — ${problem}`);
  }
  for (const { name, input, expect, detail } of CORPUS) {
    const findings = evaluate({
      published: PUB,
      unreleasedSecuritySince: null,
      consumers: [],
      ...input,
    });
    let ok;
    if (detail) {
      ok = findings.some((f) => detail.test(f.detail));
      if (!ok) console.error(`  FAIL ${name}\n       no finding matched ${detail}\n       got: ${findings.map((f) => f.detail).join(' | ') || '(none)'}`);
    } else {
      const got = findings.map((f) => f.signal);
      ok = got.length === expect.length && got.every((s, i) => s === expect[i]);
      if (!ok) console.error(`  FAIL ${name}\n       expected [${expect}] got [${got}]`);
    }
    if (!ok) failed += 1;
  }
  if (failed > 0) {
    console.error(`check-release-staleness: self-check FAILED (${failed}/${CORPUS.length})`);
    process.exit(1);
  }
  console.log(`check-release-staleness: self-check OK (${CORPUS.length} cases + consumer plumbing)`);
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
  const releasesFile = at('--releases');
  const consumersDir = at('--consumers');

  if (!releasesFile) {
    console.error('check-release-staleness: --releases <file> is required (gh api repos/OWNER/REPO/releases).');
    console.error('  Without it a bare tag is indistinguishable from a published release.');
    process.exit(2);
  }

  let published;
  try {
    published = publishedReleases(JSON.parse(readFileSync(releasesFile, 'utf8')));
  } catch (e) {
    console.error(`check-release-staleness: could not read ${releasesFile}: ${e.message}`);
    process.exit(2);
  }
  if (published.size === 0) {
    console.error('check-release-staleness: no published release with assets found — refusing to guess.');
    process.exit(2);
  }

  const newest = newestPublished(published);
  const findings = evaluate({
    changelog: readFileSync('CHANGELOG.md', 'utf8'),
    published,
    unreleasedSecuritySince: securityFirstSeenSince(`v${newest}`),
    consumers: consumersDir ? readConsumers(consumersDir) : [],
    now,
  });

  if (findings.length === 0) {
    console.log(`check-release-staleness: OK — nothing is stuck (newest published v${newest})`);
    return;
  }
  console.error(`check-release-staleness: ${findings.length} finding(s)\n`);
  for (const f of findings) console.error(`  [${f.signal}] ${f.detail}`);
  console.error('\nEach finding names work that is FINISHED but not on a device. Cut the release, re-run');
  console.error('a failed one, or open the pin PR (docs/pinning.md). No hop here is automatic, by design.');
  process.exit(1);
}

// Only run when invoked directly — the corpus and any future consumer import the pure functions,
// and an import must not execute the checker as a side effect.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
