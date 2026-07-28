#!/usr/bin/env node
// patch-kotlin-bindings.mjs — harden the generated Kotlin callback shims (SUR-1014).
//
// THE DEFECT. UniFFI 0.28.3's foreign-trait shims (`uniffiTraitInterfaceCall`,
// `uniffiTraitInterfaceCallWithError`) catch only `kotlin.Exception`, and every vtable
// call site looks up `handleMap.get(handle)` BEFORE entering the shim's guard. A
// `java.lang.Error` (OutOfMemoryError, UnsatisfiedLinkError — ordinary conditions for an
// on-device ML host) or a stale-handle `InternalException` therefore unwinds out of the
// JNA callback with `UniffiRustCallStatus` never written. A zeroed status reads as
// UNIFFI_CALL_SUCCESS, so Rust continues past a callback that produced no return value — for
// the Embedder trait, mid-`embed_pending` with the vault unlocked. (Today Rust happens to
// recover via a buffer-underflow error while lifting the unwritten return, but that is an
// accident of length-prefixed return types; a Unit-returning method would be a full silent
// success. The throwable also lands on JNA's default handler, printing the host's stack
// trace to stderr/logcat.)
//
// THE FIX, applied to the freshly generated text before it becomes the committed form:
//   A/B  both shims catch `kotlin.Throwable`; the status code is written BEFORE the error
//        buffer so a throwing lower() (real OOM) still leaves an error status; the declared
//        lane promotes to UNIFFI_CALL_ERROR only after `lowerError` succeeds; the unexpected
//        lane lowers ONLY the throwable's class name — never host-authored message content
//        ("no host string transits core", the SUR-997 crypto-review property).
//   C    every vtable `val x = FfiConverterType*.handleMap.get(...)` moves inside the
//        guard, below the hoisted argument lifts (see the transform for why the order).
//
// Upstream: UniFFI main fixes A/B (unreleased, post-v0.32.0) but lowers a host stack
// trace, and C is unfixed even there. Every transform is exact-anchor + occurrence-counted:
// a future UniFFI bump that reshapes the text makes this script HARD-FAIL (and with it the
// `bindings-drift` job) — a deliberate revisit, never a silent no-op or double-patch.
//
// Usage:  node scripts/patch-kotlin-bindings.mjs [path/to/braird_core.kt]   (in-place)
// Invoked by scripts/gen-bindings.sh; node tooling only — no crate dependency.

import { readFileSync, writeFileSync } from "node:fs";

const DEFAULT_KT = "bindings/kotlin/src/main/kotlin/uniffi/braird_core/braird_core.kt";
const file = process.argv[2] ?? DEFAULT_KT;
const MARKER = "SUR-1014 (patched post-generation)";

const fail = (msg) => {
  console.error(`patch-kotlin-bindings: ${msg}`);
  process.exit(1);
};

let src = readFileSync(file, "utf8");

if (src.includes("\r")) fail(`${file} contains CR — expected pristine LF output from uniffi-bindgen`);
if (src.includes(MARKER)) {
  console.log(`patch-kotlin-bindings: ${file} already patched — nothing to do`);
  process.exit(0);
}

const replaceExactlyOnce = (anchor, replacement, label) => {
  const count = src.split(anchor).length - 1;
  if (count !== 1)
    fail(`${label}: expected exactly 1 occurrence of anchor, found ${count} — UniFFI output changed, re-review the SUR-1014 transforms`);
  src = src.replace(anchor, replacement);
};

// ── A: no-error shim (uniffiTraitInterfaceCall). The trailing `}` closes the function and
// disambiguates this anchor from B's structurally similar else-branch.
replaceExactlyOnce(
  `    } catch(e: kotlin.Exception) {
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        callStatus.error_buf = FfiConverterString.lower(e.toString())
    }
}`,
  `    } catch(e: kotlin.Throwable) {
        // ${MARKER}: Throwable, not Exception — a java.lang.Error must not
        // escape the JNA callback with the status left UNIFFI_CALL_SUCCESS. Code before
        // buffer so a throwing lower() (real OOM) still leaves an error status; only the
        // throwable's class name crosses — never host-authored message content.
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        try {
            callStatus.error_buf = FfiConverterString.lower(e.javaClass.name)
        } catch(_: kotlin.Throwable) {}
    }
}`,
  "transform A (uniffiTraitInterfaceCall)",
);

// ── B: with-error shim (uniffiTraitInterfaceCallWithError).
replaceExactlyOnce(
  `    } catch(e: kotlin.Exception) {
        if (e is E) {
            callStatus.code = UNIFFI_CALL_ERROR
            callStatus.error_buf = lowerError(e)
        } else {
            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
            callStatus.error_buf = FfiConverterString.lower(e.toString())
        }
    }`,
  `    } catch(e: kotlin.Throwable) {
        // ${MARKER}: see uniffiTraitInterfaceCall above. The declared lane
        // sets UNIFFI_CALL_UNEXPECTED_ERROR first and promotes to UNIFFI_CALL_ERROR only
        // after lowerError succeeds, so a throwing lowerError degrades to the unexpected
        // lane instead of escaping.
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        if (e is E) {
            try {
                callStatus.error_buf = lowerError(e)
                callStatus.code = UNIFFI_CALL_ERROR
            } catch(_: kotlin.Throwable) {}
        } else {
            try {
                callStatus.error_buf = FfiConverterString.lower(e.javaClass.name)
            } catch(_: kotlin.Throwable) {}
        }
    }`,
  "transform B (uniffiTraitInterfaceCallWithError)",
);

// ── C: move every vtable handle lookup inside the guard (generic over traits — a future
// `with_foreign` trait regenerates with the same defect and is fixed here for free).
//
// Argument lifting is hoisted ABOVE the lookup, because Kotlin evaluates a call's receiver
// before its arguments: leaving the lookup as the receiver would make a handle miss abandon
// the argument `RustBuffer` — for `embedDocument` that buffer is decrypted note plaintext,
// which Rust hands over for the host to consume, so an unconsumed one is stranded on the
// Rust heap for the process lifetime. `lift` frees in a `finally`, so lifting first means the
// plaintext is always consumed, on the miss lane too. Both still sit inside the guard.
const vtableRe =
  /([ \t]*)val (\w+) = (FfiConverterType\w+\.handleMap\.get\(`?\w+`?\))\n([ \t]*val makeCall = \{ ->\n)([ \t]*)\2\.(`?\w+`?\(\n)((?:[ \t]*.+,\n)*)/g;
let vtableCount = 0;
src = src.replace(vtableRe, (_m, _indent, _v, lookup, makeCallHead, callIndent, method, argsBlock) => {
  vtableCount += 1;
  const argIndent = `${callIndent}    `;
  const args = argsBlock.split("\n").filter((l) => l.trim());
  const hoists = args
    .map((line, i) => `${callIndent}val uniffiArg${i + 1} = ${line.trim().replace(/,$/, "")}\n`)
    .join("");
  const passed = args.map((_l, i) => `${argIndent}uniffiArg${i + 1},\n`).join("");
  return `${makeCallHead}${hoists}${callIndent}${lookup}.${method}${passed}`;
});
if (vtableCount < 1) fail("transform C (vtable handle lookups): no sites matched — UniFFI output changed, re-review the SUR-1014 transforms");

// ── Post-conditions: nothing the transforms exist to eliminate may survive, including in
// shapes the anchors did not anticipate (e.g. a future async trait variant).
if (/catch\s*\(\s*\w+\s*:\s*kotlin\.Exception\s*\)/.test(src))
  fail("post-condition: a `catch(e: kotlin.Exception)` survived — an unanticipated shim variant needs a SUR-1014 transform");
if (/val \w+ = FfiConverterType\w+\.handleMap\.get/.test(src))
  fail("post-condition: an out-of-guard handleMap.get survived — an unanticipated vtable shape needs a SUR-1014 transform");

writeFileSync(file, src);
console.log(`patch-kotlin-bindings: ✓ ${file} (shims → Throwable, ${vtableCount} vtable lookup(s) moved in-guard)`);
