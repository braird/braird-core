// Where a CHANGELOG's structure actually is: which lines are section headings, and which only look
// like them because they sit inside a fence or an HTML comment.
//
// EXTRACTED, NOT WRITTEN. `check-stale-release-markers.mjs` has carried these rules since its own
// review series, and `check-release-staleness.mjs` grew a weaker copy of them one finding at a time
// — a boolean fence toggle, then a delimiter-aware one, then this. Two implementations of one rule
// is the shape that fails open: the newer copy is always the one missing a case, and nobody notices
// because the older one still passes its tests. So there is one implementation and both callers use
// it. A fix here fixes both; a gap here is visible from both.
//
// The rules are CommonMark's, restricted to what these scripts depend on:
//   - a fence delimiter takes AT MOST three leading spaces; four makes it indented code CONTENT;
//   - a fence closes only on at least the opener's run length in the SAME character;
//   - an OPENER may carry an info string (```rust); a CLOSER may carry nothing but whitespace.
//     That is what lets a ```` block quote a ``` snippet without the state desyncing.
//   - an example heading inside an HTML comment is invisible prose, not a boundary.

/**
 * Blank the INSIDE of HTML comments while preserving line structure, so a commented-out example
 * heading or fence cannot be mistaken for the real thing. Line count and column offsets are
 * unchanged, which is what lets a caller keep using the ORIGINAL lines while deciding structure
 * from this probe.
 */
export function commentBlankedProbe(text) {
  return text.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' ')).split('\n');
}

/**
 * The text with every non-structural line blanked: fenced content, fence delimiters, and the inside
 * of HTML comments. Line count is preserved, so offsets still line up with the original.
 *
 * This is what a caller that SPLITS on headings wants. Classifying the probe but splitting the
 * ORIGINAL text is a trap I walked into: the classifier correctly said "that commented-out heading
 * is not a boundary", the split then saw the original line and treated it as one anyway. If the
 * decision is made on the probe, the split has to run on the probe.
 */
export function maskedForSectionSplit(text) {
  const lines = text.split('\n');
  const structure = classifyChangelogLines(text);
  const probe = commentBlankedProbe(text);
  return lines.map((line, i) => (structure[i].insideFence ? '' : probe[i])).join('\n');
}

/**
 * Per-line structure for a CHANGELOG: `{ insideFence, heading }`, where `heading` is the version
 * label of a `## [Version]` line that is genuinely a section boundary, or null.
 *
 * Callers get the classification and decide what to do with it — masking, splitting, or counting.
 */
export function classifyChangelogLines(text) {
  const probe = commentBlankedProbe(text);
  let fence = null; // the opening delimiter run we are inside, if any
  return probe.map((line) => {
    const f = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
    if (f) {
      if (!fence) fence = f[1];
      else if (f[1][0] === fence[0] && f[1].length >= fence.length && f[2].trim() === '') fence = null;
      return { insideFence: true, heading: null }; // the delimiter line itself is never a heading
    }
    if (fence) return { insideFence: true, heading: null };
    const h = /^##\s+\[([^\]]+)\]/.exec(line);
    return { insideFence: false, heading: h ? h[1].trim() : null };
  });
}
