# Testing guide

Test task structure, gradle-discipline warnings, native variant gating, and the
native test authoring rules. This is a standalone reference guide; it is not
auto-loaded (LTS CLAUDE.md does not import guides).

## Test commands

```bash
# Default unit run (forces the pure-Java variant; see the warning below)
./gradlew test

# Per-JDK runs (skip unless the matching LTS_JDKxx env var is set)
./gradlew :core:test8
./gradlew :core:test21

# A single test class
./gradlew :pkix:test --tests org.bouncycastle.cms.test.NewSignedDataTest

# Native variant tasks (Intel host)
./gradlew clean cleanNative withNative build testAVX  -x test
./gradlew clean cleanNative withNative build testVAES -x test
./gradlew clean cleanNative withNative build testVAESF -x test

# ARM (neon-le) has no host task on an x86 build host: run it on real aarch64
# or under qemu (a docker --platform linux/arm64 run works). See native-code.md.
```

The root `./gradlew test` fans out to `:core:test :prov:test :pkix:test
:mail:test :pg:test :tls:test`. The native variant tasks are registered for
JDK 8 and JDK 21 (`testAVX8`/`testAVX21`, `testNEON8`/`testNEON21`, and so on).
The umbrella `testAVX`/`testVAES`/`testVAESF`/`testNEON` names run the
host-supported slots. Running a variant task on a CPU that lacks the feature
segfaults the JVM.

## Task structure and gradle discipline

- **Unit vs integration is a filename glob.** The unit tasks match
  `*AllTest*`; the integration tasks match `*AllIntegrationTest*`. The glob
  decides what runs, so a suite whose aggregator name matches neither silently
  never runs. Per package, `AllTests` is the unit aggregator and
  `AllIntegrationTests` the integration one.
- **The default `test` forces the pure-Java path.** It runs with
  `-Dorg.bouncycastle.native.cpu_variant=java` and a
  `-Dtest.bclts.ignore.native=...` list, so it proves nothing about the native
  code. Native verification must use the variant tasks (`testAVX`, `testVAES`,
  `testVAESF`, `testNEON`), or an equivalent forced-variant run.
- **Env-gated tasks silently skip.** The per-JDK and native variant tasks use
  `onlyIf { System.getenv(...) != null }`, so a "pass" can mean the JDK slot was
  not configured. Verify the env var is set before claiming a test ran, and
  check the result XML shows `skipped=0`. A native test that skips looks the same
  as one that passes; `-Dtest.bclts.expected_jvm` is the in-test backstop.
- **Tests are serialized on purpose.** `forkEvery = 1`,
  `maxParallelForks = 1`, and `org.gradle.parallel=false` in `gradle.properties`.
  The native library state is process-global, not per-thread. Do not add
  `parallel = true`.
- **Never run two gradle invocations against the tree at once.** A second
  `./gradlew` started while another runs clobbers the shared `build/test-results`
  and produces phantom failures across unrelated classes. It also leaves stale
  XML whose internal `timestamp` predates the run. If `BUILD SUCCESSFUL`/`BUILD FAILED`
  disagrees with a `TEST-*.xml`, suspect a concurrent run; remove the result
  XMLs, run one build, and let it finish before inspecting.
- Every test task sets `bc.test.data.home` to the absolute `core/src/test/data`.
  A new test that reads a data file uses that property.

## Testing native code

A Java roundtrip test cannot catch a native memory-safety bug, and native code
that produces wrong-but-self-consistent output passes any positive-only test.
The `*JavaAgreementTest` classes (Java vs native parity across varied chunking)
are the main net for that. These rules are the valuable, tree-agnostic part;
follow them, not the weakest existing example.

- **Prove which implementation ran.** Toggle with
  `CryptoServicesRegistrar.setNativeEnabled(false|true)` (or the forced variant)
  and assert the engine's `toString()` contains `"[Native]"` vs `"[Java]"`
  (for example `"SHA224[Native]"`, `"CTR-PS[Native]"`). Without this a silent
  Java-on-both fallback passes vacuously. Engines with no such tag (SHAKE,
  SHA-3) must instead be **instantiated directly** (`new SHAKEDigest(n)` vs the
  native class). Constructing the native class is itself proof of nativeness.
- **Probe boundaries at exactly `boundary + 1`, with a positive control at the
  boundary.** A check that is off by a constant still rejects `200`; only the
  boundary value proves the comparison sits where it should. For fixed and
  discrete-set lengths (AES key 16/24/32, GCM nonce 12) test each valid value
  and the values on each side.
- **Feed negative values into every `int` parameter** — `-1` (catches `> 0`
  written for `>= 0`) and `Integer.MIN_VALUE` (survives negation). Cover offsets,
  lengths, block counts and key sizes, alone and combined. A negative `jint` cast
  to `size_t` on the native side is huge-but-positive; the typed rejection must
  fire before the cast.
- **Null-probe every handle and array on every entry point.** A null array with
  `off == len == 0` is the case that slips past range checks (see the layering
  rules in `native-code.md`). A `bc_assert` reachable from the bridge is a JVM
  abort that only a boundary test exercises.
- **Fill every input with random bytes on every iteration — never zeros, never a
  fixed constant.** Zero and fixed inputs hide bugs (zero-over-zero copies,
  degenerate key schedules, off-by-ones landing on a zero). Seed the RNG from a
  value the test logs on failure so a flaky run is reproducible.
- **Sweep the input size across every internal buffering boundary**, and for
  ciphers vary the block chunking (`processBlocks` in one call vs block-by-block
  `processBlock`).
- **Fragment the input across every call form.** Feed the same data to the same
  engine whole, byte-by-byte (`update(byte)`), in random array chunks, and in a
  random mix. Assert all reproduce one pure-Java whole-fed reference. The
  native paths buffer differently from the Java paths, so the same input chunked
  differently is exactly where they diverge.
- **Exercise every output form** where there is more than one. A XOF has three
  distinct native paths: `doFinal(out,off)`, `doFinal(out,off,outLen)`, and
  incremental `doOutput(out,off,chunk)`; sweep output length across the rate.
- **Pre-fill output buffers with a distinct non-zero sentinel per side** so a
  native short-write cannot hide behind shared zeros.
- **Add a one-bit-corruption negative control** so the equality assertion has
  teeth: flip one input bit and assert the native output disagrees with the Java
  output of the original. For an AEAD, a damaged ciphertext, tag, or AAD must
  surface as an `InvalidCipherTextException`, not a silent decrypt.
- **Cover all key sizes and parameter sets** (AES 16/24/32, every SHA / SHAKE /
  KEM variant).
- **Gate native availability** with `TestUtil.hasNativeService(...)` /
  `TestUtil.skipPS()` and the `-Dtest.bclts.ignore.native` CSV, so an absent
  native service skips rather than fails.

## Runtime / test system properties

- `-Dorg.bouncycastle.native.cpu_variant=java|avx|vaes|vaesf|neon-le` — force a
  native variant, or `java` for pure Java.
- `-Dorg.bouncycastle.native.loader.type=...` — present in the task jvmArgs but
  inert; LTS ships one loader.
- `-Dorg.bouncycastle.packet_cipher_enabled=true` — enable the one-shot packet
  ciphers (off by default).
- `-Dtest.bclts.ignore.native=<csv>` — skip native checks for the listed
  services (for example `gcm,cbc,sha256,shake`).
- `-Dtest.bclts.expected_jvm=1.8|17|21|any` — assert the tests ran on the JDK
  they were configured for.
