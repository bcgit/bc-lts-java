# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Bouncy Castle Crypto **LTS** edition for Java — the same crypto APIs as the public BC distribution, but with optional **native (JNI) acceleration** for AES modes, SHA-2/3, GCM-SIV, DRBG, etc. on x86_64 (AVX/VAES/VAESF) and ARM64 (NEON-LE). This is **not** the FIPS distribution.

Per the README, the build targets Java 8-compatible bytecode (the build script only pins `--release 8` for `compileTestJava`; main-source compatibility is asserted in the README rather than enforced in `build.gradle`). **JAVA_HOME must point to a JDK 21** — the build tooling requires it.

## Required environment

- `JAVA_HOME` → JDK 21 (build tools require it).
- For multi-JDK test tasks (`test8`, `test11`, `test17`, `test21`), set `LTS_JDK8`, `LTS_JDK11`, `LTS_JDK17`, `LTS_JDK21` to JDK install dirs. These env vars are wired in `gradle.properties` (`org.gradle.java.installations.fromEnv`) and gate the per-JDK test tasks via `onlyIf { System.getenv(...) != null }`. Without them, `./gradlew test` only runs the default tests.

## Common commands

Java-only build (no native libs):
```
./gradlew clean cleanNative build copyJars
```

Build with native libs (you must build the native libs first — see below):
```
./gradlew clean cleanNative withNative build copyJars
```

Run native code build (Linux x86_64/ARM, OSX ARM only):
```
cd native_c && ./build_linux.sh   # or ./build_osx.sh
```
**Order matters**: `./gradlew clean compileJava -x test` before native builds — that step generates the JNI headers the C code includes.

Run a single test class (uses JUnit 4 filter):
```
./gradlew :pkix:test --tests org.bouncycastle.cms.test.NewSignedDataTest
```

The root-level `./gradlew test` fans out to `:core:test :prov:test :pkix:test :mail:test :pg:test :tls:test` (wired at the bottom of `build.gradle`) — you do **not** need to invoke each module's `test` task individually.

Reproduce a CI-style run against built jars (rather than the build classpath) with the shell harnesses:
```
./all_test.sh            # signed jars
./all_test_unsigned.sh   # unsigned jars
./mod_all_test_unsigned.sh
```
These scripts launch `java -cp <built jars + tests jar>` for each `AllTests` class and set `LD_LIBRARY_PATH=/tmp/bc-libs` (and `DYLIB_LIBRARY_PATH`) so the JVM can find the unpacked native libs outside Gradle. If a CI failure doesn't repro under `./gradlew test`, try these.

Run native-variant tests (skip pure-Java `test` task with `-x test`):
```
./gradlew clean cleanNative withNative build testAVX -x test
./gradlew clean cleanNative withNative build testVAES -x test
./gradlew clean cleanNative withNative build testVAESF -x test
./gradlew clean cleanNative withNative build testNEON_LE -x test
```
Variants assume the host CPU supports the required features — running e.g. `testVAESF` on a CPU without AVX-512 will segfault.

Verify a built jar's native status:
```
java -cp ../bc-lts-java-jars/<version>/bcprov-lts8on-<version>.jar \
     org.bouncycastle.util.DumpInfo -a
```

Force a specific native variant at runtime (debugging):
```
-Dorg.bouncycastle.native.cpu_variant=avx|vaes|vaesf|neon-le|java
```

## Architecture

### Module layout (`settings.gradle`)

| Module | Purpose |
|---|---|
| `core` | Lightweight crypto API + native bridge classes (`NativeLoader`, `NativeServices`, `Native*Provider`). All algorithm implementations live here. |
| `prov` | JCA/JCE provider (`BouncyCastleProvider`) wrapping `core`. |
| `util` | ASN.1 + shared utility classes used by `pkix`. |
| `pkix` | X.509, CMS, TSP, PKCS#12, OCSP, CRMF, CMP. |
| `tls` | TLS API + JSSE provider (`BouncyCastleJsseProvider`). |
| `mail` / `jmail` | S/MIME (legacy javax.mail and jakarta.mail variants). |
| `pg` | OpenPGP. |
| `test` | Cross-module integration tests (e.g. `NativeACVPTest`, EST tests). |
| `bctools` / `benchmark` | Internal tooling, not shipped. |
| `bom` | Maven BOM artifact. |

`core/test`, `prov/test`, `pkix/test`, etc. follow the standard Gradle layout. Test entry points are `AllTests.java` per package — the test tasks use `includeTestsMatching "AllTest*"`.

### The native-acceleration design (the LTS-specific part)

This is the part that requires reading multiple files to understand:

1. **`core/src/main/java/org/bouncycastle/crypto/NativeLoader.java`** — at static init unpacks the platform/variant `.so`/`.dylib` from inside the jar to a temp dir (`File.createTempFile` location) and `System.load`s it. The probe library detects CPU features and picks a variant; this can be overridden with `-Dorg.bouncycastle.native.cpu_variant=...`.
2. **`core/.../crypto/Native*Provider.java`** — for each algorithm there is a Java-only path and a `Native*Provider` (e.g. `NativeGCMSIVProvider`, `NativeBlockCipherProvider`). Algorithm classes (e.g. `GCMBlockCipher`, `CBCBlockCipher`) ask `NativeServices` whether a native implementation is available and either delegate or fall back to the pure-Java implementation. Both paths must produce identical outputs — when modifying an algorithm always update both.
3. **`native_c/intel/jni/*_jni.c`** — JNI entry points. The `*_pc_jni.c` variants are "packet ciphers" (one-shot encrypt/decrypt of a whole packet, gated by `-Dorg.bouncycastle.packet_cipher_enabled=true`). Native CPU dispatch happens in `native_c/intel/{aes,gcm,cbc,...}/` with one source tree per variant (avx, vaes, vaesf).
4. **JNI headers** are generated by `compileJava`. C code that `#include`s `org_bouncycastle_*.h` will not build until Java compilation has run.
5. **Cleanup**: native allocations are freed via `Cleaner`/reachability fences. The `org.bouncycastle.native.cleanup_delay` property delays free to work around aggressive GCs that can free objects mid-call on busy multicore machines.

### Behavioural difference vs. upstream BC

The native paths may **buffer** input differently than pure-Java implementations. `CipherInputStream.read(byte[])` and lightweight API `processBytes` calls can return short reads / write fewer bytes than callers might expect from the Java-only build. Always check returned lengths and use `Streams.readFully(...)` or `DataInputStream.readFully(...)` if you need a full read. This is documented at length in `README.md`.

### Test wiring

- All test tasks set `bc.test.data.home` to `core/src/test/data` (absolute path). New tests reading data files should use this property.
- `forkEvery = 1`, `maxParallelForks = 1`, plus `org.gradle.parallel=false` in `gradle.properties` — tests are intentionally serialized (native lib state is process-global). Don't try to parallelize.
- The default `test` task runs with `-Dorg.bouncycastle.native.cpu_variant=java` plus `-Dtest.bclts.ignore.native=...` (a comma-list of algorithms to skip native paths for) — i.e. it forces the pure-Java path. To exercise native code use `testAVX`/`testVAES`/`testVAESF`/`testNEON_LE`.
- `testFull` enables `test.full=true` which turns on slow/exhaustive vectors.

### Lint / static checks

- **Checkstyle 9.0** runs as part of `build` against `main` source sets only (not tests), config in `config/checkstyle/checkstyle.xml`, plus a custom `methodchecker.jar`. CI failures here are real — don't suppress.
- **`io.spring.nohttp`** plugin is applied at the root (`build.gradle:11,64`) and forbids non-HTTPS URLs in source/resources. Failures look superficially like checkstyle failures but come from a separate task — fix the URL, don't suppress.

### Versioning & jar names

`gradle.properties` carries `version=` and `maxVersion=`. Jars are named `bc{module}-lts8on-<version>.jar` (the `8on` = "Java 8 on", i.e. runs on JDK 8+). `copyJars` copies them to `../bc-lts-java-jars/<version>/`.

### Migrating from BC-FIPS

`MIGRATION.md` points at `fips_jni_to_lts.sh` — a shell script that rewrites FIPS-distribution package/import names to their LTS equivalents. Run it on a copy of the source tree, not in place.

## Things to be careful about

- **Don't `./gradlew build` after changing native code without `cleanNative withNative`** — the jar will silently ship stale `.so` files.
- **Don't change Java algorithm output without checking the matching native path** in `native_c/` (and vice versa). The same KAT vectors must pass on both.
- **Don't introduce `parallel = true`** in test config — the JNI state is global, not per-thread.
- **`./gradlew test` alone proves nothing about native code**; it forces the Java variant. Run the appropriate `testXXX` for the platform.

### Exception messages are part of the test contract

Many tests assert on exact exception message text (e.g. `isTrue(e.getMessage().equals("..."))` or `getCause().getMessage()` checks). Changing the wording of a thrown exception — even something as small as adding a colon, rewording for clarity, or wrapping with `Exceptions.illegalArgumentException(...)` — will silently break tests in another module. Before modifying any exception message, grep the whole tree for the existing string and update every matching assertion in lockstep.

### Tests must exercise the negative path

A roundtrip-only test (sign → verify, encrypt → decrypt, hash → compare, encode → decode) passes equally well against a broken implementation — a `verify()` stubbed to return `true`, a tag check that's been short-circuited, an encrypt that copies its input, a digest that returns a fixed-length zero buffer, or a parser that silently accepts any bytes will all sail through a happy-path test. Placeholder values left in during development (`return new byte[outLen];`, `System.arraycopy(in, 0, out, 0, len);`, hardcoded literals returned for the one input the author tested with) are exactly the kind of thing a positive-only test misses. For every positive test, add at least one negative case that breaks the precondition the implementation relies on:

- **Signatures / MACs** — after signing, flip a byte in the message and assert verification returns `false` (or throws). For algorithms with key consistency checks (RSA, EC, key-validating PQC schemes), also test that a corrupted public/private key is rejected at parse time or causes verification to fail.
- **AEAD** — damage the ciphertext, the tag, or the AAD independently and assert the decryptor throws `InvalidCipherTextException`. Don't rely on a single "bit-flip somewhere" test; bit-flipping AAD vs. ciphertext vs. tag exercises different code paths.
- **Block ciphers** — confirm `encrypt(p, k) != p` (the transform actually transforms), `decrypt(encrypt(p, k), k) == p`, and `decrypt(c, wrongKey) != p`. An identity stub or one that returns a constant buffer will round-trip cleanly through a test that only checks decrypt-after-encrypt with a single key.
- **Digests / XOFs** — confirm a single-bit change in the input changes the output, and that two different short inputs don't produce the same digest. A stub that returns zeros, or one that hashes only the first few bytes, will pass any test that compares only one input against one expected value.
- **KAT vectors** — pair every "input → expected output" with at least one "modified input → output differs", so an implementation that ignores some input bits can't pass. Use multiple vectors of different lengths where the spec offers them.

This matters more in this codebase than most: many algorithms have a Java path and a native path, and a pure-positive test will accept either path producing wrong-but-self-consistent output. Negative tests are often what surface a divergence between the two.

### Vary the chunking, and randomise the inputs

Streaming algorithms (block ciphers, AEAD, digests, MACs, signatures) all have a buffering layer that absorbs partial blocks. A test that only calls `processBytes(wholeMessage, 0, len)` won't exercise the partial-block path; a test that only feeds bytes one at a time won't exercise the bulk path. Implementations have shipped where one path was right and the other returned garbage — and the native paths in this codebase deliberately buffer differently from the pure-Java paths (see "Behavioural difference vs. upstream BC" above), so the same input chunked differently is exactly the case where Java and native diverge.

For every implementation with incremental input methods, run the same logical input through several chunkings and assert byte-identical output (and identical tag/MAC):

- **one shot** — single `doFinal(in, 0, len, out, 0)` (or one-shot `digest(in)` for hashes).
- **byte-by-byte** — `update(b)` repeatedly, then `doFinal`.
- **adversarial offsets** — chunks of `BLOCK_SIZE - 1`, `BLOCK_SIZE`, and `BLOCK_SIZE + 1` so partial-block boundaries land in different places, plus a chunk that spans the last block (catches finalisation bugs).
- **random splits** — partition the message at random offsets so chunk boundaries don't always coincide with algorithmic alignments.

The same matrix applies to digest `update` vs. one-shot, and to incremental signature/MAC `update` vs. building the message buffer up-front. For AEAD, AAD chunking is independent of plaintext chunking — vary them separately.

When the test isn't anchored to a published KAT (i.e. a roundtrip comparing `decrypt(encrypt(x)) == x` rather than against a fixed expected output), use fully random values for **everything** — key, IV / nonce, AAD, plaintext content, and plaintext length. Hardcoded inputs let bugs hide in alignment-, length-, or value-specific code paths: an off-by-one in CTR counter handling that only fires past a certain block count, a GCM length encoding bug that only triggers when AAD length mod 16 is zero, a digest finalisation bug that only fires when the input length is a multiple of the block size. Seed `SecureRandom` from a value the test logs on failure so a flaky run is reproducible.

### Boundary-test key, IV, and nonce lengths

Fixed-length validation is often condensed into a compact single-expression check — bit operations combining `& ~`, an `|` of differences, or arithmetic that folds three valid AES key lengths into one branch. These are easy to get subtly wrong (a check that accepts 17 alongside 16, or rejects 32 because of a mask typo) and the bug is invisible to any test that only ever exercises a valid length. Whenever you add a test for an input that has a length constraint, also test the values immediately on each side of the spec'd length and assert the implementation rejects with the expected exception:

- **Single fixed length** (e.g. GCM-SIV / GCM nonce = 12) — test 11, 12, 13. Also 0 and `null`.
- **Discrete valid set** (e.g. AES key ∈ {16, 24, 32}, or {16, 32} where 24 is rejected) — test every valid length, plus the boundaries: 15, 17, 23, 25, 31, 33. Also 0, 1, and a value well above the maximum (e.g. 64) so a check that only enforces an upper bound can't slip through.
- **Permitted range** (e.g. an HMAC key with a min and max) — test `min - 1`, `min`, `max`, `max + 1`.

Apply the matrix to keys, IVs, nonces, and salts **independently** — a missing IV-length check is easy to hide if a key-length check happens to fire first. And confirm the exception type matches the contract (`IllegalArgumentException` from `init`, `InvalidKeyException` from JCE entry points); a `bc_assert` abort on the C side looks identical to a clean failure from a poorly-written test, so verify the rejection reaches Java as a typed exception rather than a process abort.

### Feed negative values into every integer parameter

Java `int` is signed; nearly every API in this codebase that takes a length, offset, count, or size declares it as `int`. Range checks that look fine in passing — `if (len > buffer.length) throw ...` — silently accept negative values, and the negative then propagates into a `size_t` cast on the JNI side, an allocation expression like `new byte[len + 16]` (`len = -1` becomes a 15-byte buffer, no exception), or pointer arithmetic that reads before the start of the input. For every test you write that calls a method with an `int` parameter — `inOff`, `len`, `outOff`, `iterations`, `macSize`, `keySize`, `ivLen` — also test:

- **`-1`** — catches checks written `len > 0` instead of `len >= 0`, and conditionals comparing in the wrong direction.
- **`Integer.MIN_VALUE`** — special-cases anywhere the implementation does `Math.abs(len)` or `-len`, both of which are still negative for `MIN_VALUE` and overflow silently.
- **Combinations** — negative offset with valid length, valid offset with negative length, both negative. A bug that's masked when one parameter is sane is still there when the other is the one being checked first.

For methods that cross the JNI boundary this matters more — a negative `jint` cast straight to `size_t` becomes ~2³² (or ~2⁶⁴ on 64-bit hosts), which then drives either a runaway allocation or a `memcpy` that reads memory the caller never owned. Verify the rejection happens at the Java boundary or as an explicit C-side check **before** the cast, and surfaces as a typed exception rather than a segfault.

### Update `module-info.java` when you add a package

Each module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java` (e.g. `core/src/main/jdk1.9/module-info.java`) listing every exported package. The Java 8 sources under `<module>/src/main/java` and the descriptor are bundled into the same multi-release jar; the descriptor is the source of truth for what's visible when downstream code runs on JDK 9+ with `--module-path`. A package that exists in the source tree but isn't listed in `module-info.java` is invisible to modular consumers — class-path consumers still see it, which is why the omission is easy to miss locally.

When you add a class, ask which case applies:

- **Existing package** (e.g. dropping `ECBModeCipher` into `org.bouncycastle.crypto.modes`, already on line 40 of `core/.../module-info.java`) — no descriptor change needed. `module-info.java` exports packages, not classes.
- **New package** (a directory that doesn't yet exist under any `org.bouncycastle.*` tree) — add `exports org.bouncycastle.your.new.package;` to the corresponding module's `module-info.java`. The modules are `core`, `prov`, `util`, `pkix`, `tls`, `mail` / `jmail`, `pg` — pick the one whose `src/main/java` your new package physically lives under.

Symmetrically, if you delete or merge away an entire package, remove its `exports` entry. The compile-time signal that catches a missed entry — `module org.bouncycastle.lts.core does not export org.bouncycastle.crypto.foo` — only fires for modular downstream consumers, so a class-path-only test run won't surface it.

