---
name: reconcile-residuals
description: Find and adopt hidden stale-source residuals in a bc-lts-java module index (files whose recorded index == upstream but whose local source is behind), then verify with tests + japi. Use when asked to "scan <module> for stale files", "reconcile residuals", "check the <module> index against upstream", or adopt upstream security/robustness fixes the LTS edition is missing.
---

# Reconcile hidden stale-source residuals

A **hidden stale-source residual** is a file whose `indexes/bc-java.<mod>.index` hash already equals the
current upstream hash, but whose *local* source is an older version. `check-indexes.sh` compares
recorded-vs-upstream only, so it is blind to these. See CLAUDE.md ("The hidden stale-source residual" and
"API compatibility gate") for background — this skill is the operational procedure.

Upstream bc-java checkout: `../../bc-java` (resolve the real path if that's a symlink/missing; CLAUDE.md's
default is `../../bc-java`). Modules: `core util prov pkix pg tls mail`.

## 1. Scan the module index for candidates

Signature: `recorded == upstream` AND `local != upstream`. For the `core` index only, remap the 13 asn1 OID
subpackages `core->util` (`cryptlib|edec|gnu|isara|iso|kisa|microsoft|misc|mozilla|nsri|ntt|oiw|rosstandart`),
matching `check-indexes.sh`; no remap for the other modules.

```bash
UP=../../bc-java; mod=<MODULE>; idx=indexes/bc-java.$mod.index
while read -r hash path; do
  [ -z "$hash" ] && continue
  up="$path"
  # core-only OID remap:
  case "$mod:$path" in core:*/org/bouncycastle/asn1/@(cryptlib|edec|gnu|isara|iso|kisa|microsoft|misc|mozilla|nsri|ntt|oiw|rosstandart)/*) up="${path/core/util}";; esac
  [ -f "$path" ] && [ -f "$UP/$up" ] || continue
  u=$(sha256sum "$UP/$up"|cut -d' ' -f1); l=$(sha256sum "$path"|cut -d' ' -f1)
  [ "$hash" = "$u" ] && [ "$l" != "$u" ] && echo "$path"
done < "$idx"
```
Exclude paths you edited earlier this session (`git log --name-only --pretty=format: <session-start>~1..HEAD`).
Rank by strictly-behind signal: `diff -w <upstream> <local>` — few local-only (`<`) lines + many upstream-only
(`>`) lines = residual; lots of local-only = curation / LTS-ahead.

## 2. Triage (do NOT blind-adopt — the candidate set includes deliberate divergences)

For each candidate read `diff <upstream> <local>` and classify:
- **STALE** — local is an older upstream, no LTS reason to differ → adopt. Risk: HIGH (missing security/
  correctness fix: bounds/null/range check, malformed-input rejection, DoS cap, verify/MAC change), MED
  (functional/robustness gap), LOW (additive getter/constant/deprecated overload, or test-only).
- **INTENTIONAL** — leave. Curation (dropped `X509Name`/`X509Extensions`/PQC/lightweight-AEAD/CMS-DL-streaming),
  native-acceleration hooks (`*.newInstance()` digest factories, `Native*`), `BufferedBlockCipher`-as-interface,
  LTS-ahead, or **blocked-by-curation** (upstream references a class/method absent from the LTS tree).
- **COSMETIC** — leave. Javadoc/whitespace/import-order only.

For a large candidate set, fan this out to parallel subagents (one batch of ~12-15 files each). Require each
to also state **verbatim-safe vs needs-surgical vs ABI-break** (see step 4).

## 3. Adopt STALE files in themed batches

Verbatim `cp` the upstream file when it is a pure residual (local a strict subset). Go **surgical** (graft only
the security-relevant hunk) when the file also carries LTS curation or LTS-ahead hardening you must preserve.
Common re-break after a verbatim `cp`: `new BufferedBlockCipher(...)` (an interface in LTS) → change to
`new DefaultBufferedBlockCipher(...)`.

After each batch: recompile the module (`:mod:compileJava :mod:compileTestJava` + MR sets
`compileJava11Java`/`compileJava15Java`/`compileJava17Java`), then run the affected suites — SimpleTest
`RegressionTest`s standalone (fastest KAT; classpath `<mod>/build/classes/java/{main,test}` +
`core/build/classes/java/main` + resources + `junit`/`hamcrest` from `~/.gradle/caches`,
`-Dbc.test.data.home=core/src/test/data`) and JUnit `AllTests` via `org.junit.runner.JUnitCore`. If a test NPEs
loading a resource, run `:mod:processTestResources` (stale `build/resources/test` is a common false alarm).

## 4. Verify the API gate (MANDATORY before commit)

Run `japi-compliance-checker` for the built lib(s) — see CLAUDE.md "API compatibility gate". "Verbatim-safe to
compile" is NOT binary-compatible: watch for removed/changed constructors, changed return/param types, a public
class made abstract, or a method added to a public interface. Any of those fails the gate — revert the file and
graft only the additive/internal part. Gate = 0 removed / 0 high-severity for `bccore bcprov bcutil bcpkix bcpg
bctls` vs the last released jar under `../bc-lts-java-jars/`.

## 5. Commit

One themed commit per batch, describing what was adopted, why each was safe, and what was deferred/skipped
(ABI break, blocked-by-curation, bidirectional divergence). Never bump an index just to silence check-indexes;
a clean adoption already matches the recorded hash, and a deliberate surgical divergence stays at the upstream
baseline. No `Co-Authored-By` trailers.
