// Where a CHANGELOG's structure actually is: which lines are section headings, and which only look
// like them because they sit inside a fence or an HTML comment.
//
// EXTRACTED, NOT WRITTEN. `check-stale-release-markers.mjs` carried these rules through its own
// review series, and `check-release-staleness.mjs` grew a weaker copy of them one finding at a time.
// Two implementations of one rule is the shape that fails open: the newer copy is always the one
// missing a case, and nobody notices because the older one still passes its tests. So there is one
// implementation and both scripts import it — a fix here fixes both; a gap here is visible from both.
//
// The rules are CommonMark's, restricted to what these scripts depend on:
//   - a fence delimiter takes AT MOST three leading spaces; four makes it indented code CONTENT;
//   - a fence closes only on at least the opener's run length in the SAME character;
//   - an OPENER may carry an info string (```rust); a CLOSER may carry nothing but whitespace, which
//     is what lets a ```` block quote a ``` snippet without the state desyncing;
//   - a BACKTICK fence's info string may not itself contain a backtick, so an ordinary line does not
//     open a block that then masks the rest of the file;
//   - an example heading inside an HTML comment is invisible prose, not a boundary — but comment
//     syntax is LITERAL TEXT inside a fence, so the two states have to be resolved together.
//
// That last clause is why this is ONE INTERLEAVED PASS rather than a comment-blanking pre-pass
// followed by fence detection. Blanking comments first lets a `<!--` written inside a fenced example
// swallow that fence's closing delimiter; the fence then never closes and every following line,
// including a real `### Security`, is masked to EOF. Precedence has to be decided per line, in
// order, because each state can hide the other's syntax.

const FENCE = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const VERSION_HEADING = /^ {0,3}##\s+\[([^\]]+)\]/;

/**
 * Blank any HTML-comment span on one line, carrying the open/closed state across lines.
 *
 * `hasCloserAfter(offset)` decides whether a `<!--` is a real comment opener or just prose. Without
 * that lookahead an UNTERMINATED marker masks everything to end of file, and the likeliest source of
 * one is a CHANGELOG entry *describing* comment syntax — which is exactly how this shipped broken:
 * the entry documenting the comment handling contained a literal `<!--`, and the parser reading that
 * entry then found zero sections in its own file.
 *
 * An unterminated marker is therefore treated as literal text. That direction is deliberate: masking
 * fails toward SILENCE, which is the failure mode this whole checker exists to avoid, while treating
 * it as prose fails toward noise. A genuinely forgotten `-->` shows up as findings, not as quiet.
 */
function maskComments(line, openAtStart, lineOffset, hasCloserAfter) {
  let open = openAtStart;
  let out = '';
  let i = 0;
  while (i < line.length) {
    if (open) {
      const end = line.indexOf('-->', i);
      if (end === -1) {
        out += ' '.repeat(line.length - i);
        i = line.length;
      } else {
        out += ' '.repeat(end + 3 - i);
        i = end + 3;
        open = false;
      }
    } else {
      const start = line.indexOf('<!--', i);
      if (start === -1) {
        out += line.slice(i);
        i = line.length;
      } else if (!hasCloserAfter(lineOffset + start)) {
        out += line.slice(i); // prose mentioning the marker, not a comment
        i = line.length;
      } else {
        out += line.slice(i, start);
        i = start;
        open = true;
      }
    }
  }
  return { masked: out, open };
}

/**
 * Per-line structure: `{ insideFence, heading, masked }`, where `heading` is the version label of a
 * `## [Version]` line that is genuinely a section boundary, and `masked` is the line with any
 * comment span blanked (length preserved, so offsets still line up with the original).
 *
 * Precedence is the design: inside a fence, comment syntax is literal and only a valid closing
 * delimiter matters. Outside one, a comment hides everything it contains — fence markers included.
 */
export function classifyChangelogLines(text) {
  let fence = null; // the opening delimiter run we are inside, if any
  let inComment = false;
  let offset = 0;
  const hasCloserAfter = (at) => text.indexOf('-->', at) !== -1;
  return text.split('\n').map((raw) => {
    const lineOffset = offset;
    offset += raw.length + 1; // + the newline the split consumed
    if (fence) {
      const f = FENCE.exec(raw);
      if (f && f[1][0] === fence[0] && f[1].length >= fence.length && f[2].trim() === '') fence = null;
      return { insideFence: true, heading: null, masked: '' };
    }
    const { masked, open } = maskComments(raw, inComment, lineOffset, hasCloserAfter);
    inComment = open;
    const f = FENCE.exec(masked);
    if (f) {
      if (f[1][0] !== '`' || !f[2].includes('`')) fence = f[1];
      return { insideFence: false, heading: null, masked };
    }
    const h = VERSION_HEADING.exec(masked);
    return { insideFence: false, heading: h ? h[1].trim() : null, masked };
  });
}

/**
 * The text with every non-structural line blanked: fenced content, fence delimiters, and the inside
 * of HTML comments. Line count is preserved, so offsets still line up with the original.
 *
 * This is what a caller that SPLITS on headings wants. Classifying a probe but splitting the
 * ORIGINAL text is its own trap: the classifier correctly says "that commented-out heading is not a
 * boundary" and the split then sees the original line and treats it as one anyway.
 */
export function maskedForSectionSplit(text) {
  return classifyChangelogLines(text)
    .map(({ insideFence, masked }) => (insideFence ? '' : masked))
    .join('\n');
}
