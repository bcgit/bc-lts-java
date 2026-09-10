# Java build & project guide

The gradle build, multi-release jar rules, native-reference lifetime, and
Java-side conventions. This is a standalone reference guide; it is not
auto-loaded (LTS CLAUDE.md does not import guides).

## Required environment

`JAVA_HOME` must point to a JDK 21 — the build tooling needs it. Set the
per-JDK toolchain homes too; the build resolves them through
`org.gradle.java.installations.fromEnv` in `gradle.properties`:

```
LTS_JDK8 LTS_JDK11 LTS_JDK17 LTS_JDK21
```

The per-JDK test tasks (`test8`, `test11`, `test17`, `test21`) and the native
variant tasks are gated with `onlyIf { System.getenv(...) != null }`. They
silently skip if the matching env var is unset, so a "pass" can mean the JDK was
not configured. See the env-gating warning in `testing.md`.

## Common build commands

```bash
# Java-only build (no native libs in the jar)
./gradlew clean cleanNative build copyJars

# Build with native libs bundled (build native_c first; see native-code.md)
./gradlew clean cleanNative withNative build copyJars

# Skip tests during a build
./gradlew clean cleanNative build copyJars -x test

# Verify a built jar's native status
java -cp ../bc-lts-java-jars/<version>/bccore-lts8on-<version>.jar \
     org.bouncycastle.util.DumpInfo -a

# Checkstyle / nohttp / module checks (no tests)
./gradlew clean build check -x test
```

`copyJars` copies the module jars to `../bc-lts-java-jars/<version>/`. The
cross-module discipline analog to a companion-jars story is `check-indexes.sh`
and the `indexes/` manifests, which track which LTS sources match or diverge
from upstream `bc-java`; see the index section of the project CLAUDE.md.

## Multi-release jar layout

The multi-release source sets are per-module and wired in each module's
`build.gradle`.

- **`core`** has only `src/main/java` and `src/main/jdk1.9`. The base compiles to
  `--release 8`; `jdk1.9` compiles to `--release 9` and packages into
  `META-INF/versions/9/`. The JPMS descriptor lives at
  `core/src/main/jdk1.9/module-info.java`.
- **`prov`** has `jdk1.9`, `jdk1.11`, `jdk1.15` and `jdk17`. `compileJava17Java`
  uses `sourceCompatibility`/`targetCompatibility = 17`, not `options.release =
  17`: the ML-KEM JCE SPIs reference `javax.crypto.KEM` (JEP 452, backported to
  Java 17 at run time). `--release 17` hides it behind the JDK 17 symbol set.
  Do not "fix" this back to `options.release`.

**Apply edits to every override copy.** A change to a class that has a `jdkN`
override must land in the baseline **and** in every override copy of the method.
Nothing guards against drift. The **public/protected API surface must be the
same** across all copies. Downstream code compiles against the Java 8 ABI, so a
public member added only to a `jdkN` copy is invisible to callers. One removed
only from a `jdkN` copy throws `IllegalAccessError` at run time on that JDK.
Private and package-private members may differ.

**module-info exports.** A new package must be added as an `exports` entry in the
module's `module-info.java` (under `jdk1.9`) or it is invisible to modular
consumers; class-path consumers still see it, so the omission passes local
testing. Remove the entry when you delete a package.

## Native-reference lifetime (Java side)

Every `*Native*` engine or digest class holds its native context through an
`org.bouncycastle.util.dispose.NativeReference`. Its disposer frees the C-side
ctx when the reference is unreachable; the `DisposalDaemon` is reference-queue
driven. The holding object must stay reachable across every native call.
Otherwise the GC can reclaim it mid-call, run the disposer, and leave native
code dereferencing freed memory. Two patterns, split by source set:

- Base `src/main/java` (Java 8): wrap the native call in `synchronized (this) {
  ... }`; the monitor keeps `this` reachable for the block.
- `src/main/jdk1.9`: `try { native call } finally {
  Reference.reachabilityFence(this); }` — the explicit fence, the modern form.

Every `jdk1.9` override of a native-backed class re-implements this pairing (the
overlay copy is the baseline with each `synchronized` block converted to the
fence form). A new native-backed class must ship **both** halves. A raw native
call guarded by neither is a latent use-after-free even if tests pass. The
`org.bouncycastle.native.cleanup_delay` property delays the free to work around
aggressive GCs that can free an object mid-call on busy multicore machines.

## Module layout and the API-stability gate

The modules are `bom`, `core`, `prov`, `util`, `pkix`, `tls`, `mail`/`jmail`,
`pg`, `test`, `bctools` and `benchmark`. `core` holds the lightweight crypto API
and the native bridge classes; `prov` is the JCA/JCE provider wrapping `core`.
There is no FIPS integrity boundary here — no HMAC checksum, no `FipsStatus`, no
signed jar. `core` ships **both** as the standalone `bccore` jar **and** folded
into `bcprov`, so a `core` change affects both artifacts.

The release is bound by an **API-stability gate**, not an integrity checksum:
`japi-compliance-checker` must report **0 removed methods and 0 high-severity
problems** for every shipped lib (`bccore`, `bcprov`, `bcutil`, `bcpkix`,
`bcpg`, `bctls`). The rule is "preserve the existing public API, only add." An
edit fails the gate, even when it compiles and tests pass, if it:

- removes or changes a public constructor, return type, or parameter type;
- makes a public class abstract; or
- adds a method to a public interface.

See the japi section of the project CLAUDE.md for the baseline and command.

## Style / build hygiene

- Checkstyle (`config/checkstyle/checkstyle.xml`) runs as part of `check` over
  the **`main` source sets only**, so `src/test/java` and `module-info.java` are
  not linted. The config enforces **Allman braces** (`LeftCurly` `option=nl` —
  `{` on its own line) and bans pure-whitespace lines. Code ported from upstream
  bc-java (K&R braces, trailing-whitespace blank lines) must be reformatted, or
  it fails `check`. The custom `DebugMethodChecker` checkstyle module is loaded
  from `config/checkstyle/lib`.
- The `io.spring.nohttp` plugin is applied at the root and forbids non-HTTPS URLs
  in source and resources. A nohttp failure looks like a checkstyle failure but
  comes from a separate task; fix the URL, do not suppress.
- The core test task runs on the JUnit Platform (`junit-jupiter` 5.14.3). Many
  existing tests extend `junit.framework.TestCase` or `SimpleTest` and some are
  Jupiter; match the convention of the file you are editing, not the project as a
  whole.
