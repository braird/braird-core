// V8 `normalizeForTag` oracle for the Rust differential fuzz (src/normalize.rs).
//
// EXACT mirror of surfc/src/lib/text.js `normalizeForTag` — the canonical JS source of
// truth. Keep in sync by hand (it is 8 lines and frozen wire-format behaviour); the
// vendored golden vectors remain the drift-guarded cross-repo contract, while this file
// is the oracle the fuzz diffs the Rust port against over a large generated corpus.
//
// Usage: `node normalize_oracle.mjs <corpus.json>` where corpus.json is a JSON array of
// strings. Writes a JSON array of the normalized results to stdout. Must run on a Node
// whose V8/ICU implements the parity anchor (Unicode 17.0 → Node v24.15.0).
import { readFileSync } from 'node:fs'

function normalizeForTag(text) {
  if (!text) return ''
  return String(text)
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\p{Cc}/gu, '')
    .trim()
    .replace(/[\p{P}]+$/u, '')
    .trim()
}

const corpus = JSON.parse(readFileSync(process.argv[2], 'utf8'))
process.stdout.write(JSON.stringify(corpus.map(normalizeForTag)))
