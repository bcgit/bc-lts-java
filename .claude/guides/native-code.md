# Native code guide (`native_c/`)

Building the native variants, the ARM feature-gating model, and the rules for
authoring and reviewing C. This is a standalone reference guide; it is not
auto-loaded (LTS CLAUDE.md does not import guides). Read the native-acceleration
section of the project CLAUDE.md first.

## Build

The build is CMake-based and separate from gradle. It builds the Intel variants
(`avx`, `vaes`, `vaesf` under `target/linux/x86_64/`) and ARM (`neon-le` under
`target/linux/arm64/`). The `withNative` gradle task copies these into
`core/src/main/resources/native/` before `jar`. `cleanNative` removes that
resources copy.

```bash
export JAVA_HOME=$LTS_JDK21
./gradlew clean cleanNative :core:compileJava -x test   # generate the JNI headers first
cd native_c && ./build_linux.sh                         # x86_64; or ./build_linux_arm.sh for aarch64
```

Order matters: `compileJava` generates the `org_bouncycastle_*.h` headers the C
files include, so it must run before the native build.

**The stale-library footgun.** `build_linux.sh` installs into
`target/linux/x86_64/<variant>/`; `withNative` copies those into the resources
tree; `cleanNative` deletes the resources copy. A `./gradlew build` without
`withNative`, or a `build` after `cleanNative`, ships a jar with no native
libraries or with stale ones. Always run `clean cleanNative withNative build`
together, and check the `.so` timestamps against the C source before trusting a
result.

Forcing a variant whose CPU features the host lacks segfaults the JVM. Use
`-Dorg.bouncycastle.native.cpu_variant=<name>` deliberately (see the property
list in `testing.md`).

**ARM march floor and per-service gating.** The Linux ARM variant is compiled at
the support floor `-march=armv8-a+crypto` (Graviton 1/2 / Neoverse-N1 class).
Only the translation units in the `set_source_files_properties` block in
`CMakeLists.txt` (`sha384.c`, `sha512.c`, `sha3.c`, `shake.c`) may contain
FEAT_SHA512 or FEAT_SHA3 instructions. Each carries a per-file `-march`, and each
service is runtime-gated by the requirement table in `arm/jni/services.h`, which
reads the HWCAPs through `getauxval(AT_HWCAP)` in `arm/jni/native_features.c`. A
service whose HWCAP is missing is switched off and served by pure Java, never a
SIGILL. When a kernel gains a new instruction-set dependency: add the HWCAP probe
in `native_features.c`, the feature bit and service mask in `services.h`, and the
per-file `-march` in CMake. Never raise the global baseline. This is the fix for
the Graviton 2 `EOR3` SIGILL (issue #2253): `qemu-aarch64 -cpu neoverse-n1` is
the Graviton-2 stand-in for regression-testing the knockout.

## Reviewing native C code

The JNI bridges (`native_c/{intel,arm}/jni/`) and the algorithm implementations
(`intel/{aes,cbc,cfb,ctr,ecb,gcm,gcm_siv,sha,ccm,packet,...}`, `arm/...`, shared
`jniutil/`, `util/`) have distinct responsibilities. A Java roundtrip test cannot
catch a memory-safety bug in native code, and a function that produces
wrong-but-self-consistent output sails through any positive-only test. The
`*JavaAgreementTest` classes (Java vs native parity, varied chunking) are the
main net for that class, so keep them honest. See `testing.md` for the authoring
recipes.

### Layering: bridges validate, implementations trust

- **The bridge is the only layer that validates application inputs.** It
  surfaces a failure as a typed Java exception through the `jniutil/exceptions.c`
  helpers (`throw_java_NPE`, `throw_java_illegal_argument`,
  `throw_java_invalid_state`, `throw_bc_data_length_exception`,
  `throw_bc_output_length_exception`, `throw_bc_invalid_ciphertext_exception`);
  the packet ciphers return a `packet_err` that the JNI wrapper maps to the same
  exceptions. Before touching an array: null-check, sign-check every
  offset and length **before any `(size_t)` cast**, and bound offset+length pairs
  with `check_range(size, offset, len)` from `jniutil/jni_asserts.h`, which
  compares without overflow. The helpers `bytearray_not_null`,
  `critical_not_null` and the `*_in_range_for_offsets_and_len` forms wrap the
  common cases.
- **The explicit null-check must come first.** A null Java array loads as
  `array == NULL, size == 0`, and `check_range(0, 0, 0)` **passes**. A null array
  with zero offset and length slips through every range check and reaches the
  implementation unless the bridge null-checks it first.
- **`bc_assert` vs a thrown exception.** `bc_assert` (in `util/util.h`) aborts
  the process. Use it only for conditions that our own code can violate, never
  for a value that came from the application. Keys, IVs, nonces, data buffers,
  offsets, lengths and key sizes get a typed exception that surfaces in Java;
  they must never reach an assert. Use `bc_assert` (always live), never
  `<assert.h>` `assert` (compiles out under `-DNDEBUG`).
- **Implementations trust the bridge.** Algorithm code (`cfb_ctx`, `gcm_ctx`,
  `ctr_ctx`, SHA states) asserts bridge-validated preconditions as invariants
  (`bc_assert(ctx != NULL)`) rather than re-validating. Input validation inside
  an implementation is a smell; move it to the bridge.

### Packet-cipher bridge rules

The one-shot packet ciphers (`intel/packet/{cbc_pc,ccm_pc,cfb_pc,ctr_pc,gcm_pc,gcm_siv_pc}`)
take the key, input and output in a **single** call, so they carry hazards the
streaming bridges do not.

- **A read-only input array must not be committed back over an aliased output.**
  The application may pass the same Java array as key and as output (for example
  `KeyParameter.getKey()` as the destination). The critical output is committed
  first, so a later mode-0 release of the key would overwrite the ciphertext with
  the stale key (finding C07-02). Release every read-only input array (key, IV,
  AAD) with `release_bytearray_ctx_unchanged` (JNI_ABORT), never the mode-0
  `release_bytearray_ctx`. A mode-0 release is only for an array the native code
  wrote.
- **One-shot validation must cover everything the streaming split validates in
  two places.** The streaming path validates at init and again at process; the
  packet path has one entry. So it must validate the key size, IV length,
  IV-derived counter range, and input and output bounds up front, and be
  failure-atomic (finding C05-01).

### Bug classes to review for

**Logic errors and inverted conditions.** Where a function uses the "1 = success"
convention, prefer `if (1 != foo(...))` over `if (!foo(...))` — robust to a
future -1 return. Off-by-ones hide between `>=` and `>` on length checks;
goto-fallthrough where an error path falls into the success path because the
block before `exit:` does not `return`. Order-of-call bugs (a ctx configured
after the call that needed the value) pass silently and produce
wrong-but-consistent output — only an agreement test catches them.

**Missing returns and pointer-vs-value confusion.** Audit every path of a
value-returning function. Never return or store the address of a stack local.

**Dangling pointers and free-after-use.** The lifecycle structs (`cfb_ctx`,
`gcm_ctx`, `ctr_ctx`, SHA states) are reused across init/update/final/reset. NULL
out a field after freeing what it points to, or the next lifecycle call
double-frees. Every `init_critical_ctx`/`load_*_ctx` pairs with its
`release_*_ctx` on **every** exit path; mirror that pattern for any new resource
helper.

**Cleanup on every error path.** With `goto exit`, declare every resource pointer
at the top of the function and set it to NULL before any branch can jump; freers
at the label must be NULL-tolerant and called unconditionally. Erase secret
material (key schedules, post-decrypt plaintext, DRBG output, anything
key-derived) with `memzero`, never a plain `memset` before free. On both arches
`memzero` is hand-written assembly (`intel/util/memzero_sysV.asm`,
`arm/util/memzero_aarch64.S`) that no C optimiser can delete; there is no C
implementation. Every assembly source must end with the `.note.GNU-stack` and
`.note.gnu.property` sections. Each exported function starts with its landing
pad (`endbr64` on Intel, `hint #34` on ARM). `build_linux.sh` fails the build on
an executable-stack library, and one object without the GNU property strips the
CET or BTI marking from the whole `.so`. See `asm-porting.md`.

**Integer overflow and signed-to-unsigned casts.** Every length and offset
crossing the JNI boundary is a signed `jint` (or a `jlong`). A negative value
cast to `size_t` becomes huge-but-positive, passes `len > 0`, and drives a
`memcpy` over memory the caller never owned; validate the sign **before** the
cast. Allocations like `n * sizeof(T)` or `len + 16` need an upper bound to avoid
wraparound. Casting `size_t` back to `jint` needs an explicit `> INT32_MAX`
check.

**Wider-lvalue access to a caller pointer.** A java array reaches native code as a
`uint8_t *`, often at a caller-chosen offset, so it carries byte alignment only.
Casting it to a wider type and accessing through that type is undefined
behaviour, on alignment and on strict aliasing. Two shapes appear:

- a scalar lvalue, `uint32_t *p = (uint32_t *) (out + 16); p[0] = v;`
- an intrinsic argument, `vld1q_u32((uint32_t *) &block[0])`

Fix the first with `memcpy(out + 16, &v, sizeof(v))`. Fix the second with the
byte-pointer form of the same intrinsic, `vreinterpretq_u32_u8(vld1q_u8(&block[0]))`.
Both fold back to the same single instruction. Confirm that by disassembly, and
treat any real codegen change as a finding to raise before you proceed.

**A sanitiser cannot find the intrinsic shape. Silence there is not evidence.**
`-fsanitize=alignment` instruments C lvalue accesses. It does not instrument a
pointer handed to an intrinsic. Measured in this tree: a misaligned
`vld1q_u32((uint32_t *) p)` ran clean under UBSan, while a misaligned
`q[0] = v` in the same build halted with "store to misaligned address". So a
clean UBSan column means something only with two positive controls:

- prove the misaligned path really ran. Show that the output changes with the
  offset.
- prove the build can report at all. Fire it on a scalar store you inserted.

**The guard against the cast returning is this sweep, not a test.** The fixes
above emit the same machine code, so the output does not change. **No
output-comparison test can detect a regression here.** Run the sweep instead:

```bash
# candidate sites: wider-typed casts, excluding the safe byte and void forms
grep -rnE "\((uint16_t|uint32_t|uint64_t|unsigned long long|size_t|int|long) \*\)" \
     native_c --include=*.c --include=*.h | grep -vE "\(void \*\)|\(char \*\)|\(uint8_t \*\)|\(const "
# alignment-requiring SSE forms; the unaligned "u" variants are the safe ones
grep -rnE "_mm(256|512)?_(store|load)_si(128|256|512)\b" native_c --include=*.c --include=*.h
```

Then, for each hit, decide whether a caller offset can reach it, and disassemble
to see the instruction actually emitted. An intrinsic argument that no rewrite
can express in byte-pointer form may be accepted as a residual. Record the
reasoning and the reachability when you accept one.

**String functions.** `strcpy`, `strcat`, `sprintf`, `gets` are banned.
`strncpy` does not NUL-terminate when the source is longer than the destination;
write the NUL or use `snprintf`. Strings really only appear in the probe and
variant-selection code; keep it that way.

**Side channels.** Never `memcmp` a tag, a MAC, or anything secret-derived; it
short-circuits and leaks the matched-prefix length. Use `areEqualCT`
(`intel/gcm/gcm128w.c` / `gcm512w.c`) as the GCM tag check does, or
`tag_verification` for the packet AEAD path. No branching on secret bits, no
array indexing by secret values, no loop whose trip count depends on a secret.

**JNI exception state and reference lifetime.** After any JNI call that can throw
(`NewByteArray`, `FindClass`, `NewObject`), check `ExceptionCheck` before the
next JNI call; calling through a pending exception is undefined behaviour. Loops
that make local refs need `DeleteLocalRef` for each one or `EnsureLocalCapacity`
up front. `JNIEnv*` is per-thread. Inside a `GetPrimitiveArrayCritical` region no
JNI up-calls are allowed; fetch randomness, allocate outputs and resolve classes
before the region or after it.

**Symbol naming.** LTS ships no version script, so every exported symbol is
public and is resolved by the dynamic loader against everything in the host
process. A JVM that also loads libcrypto or another native library can shadow a
generic name and produce an impossible-looking SIGSEGV in foreign code. JNI
exports use the mandated `Java_<class>_<method>` names, so they do not collide.
Give any **other** new export a distinctive, collision-unlikely name and check
`nm -D --defined-only <lib>.so` before committing.

**`memcpy` vs `memmove`.** Overlapping ranges through `memcpy` are undefined even
when they happen to work; shifting a buffer onto itself
(`memcpy(buf, buf + off, n)` with `off < n`) needs `memmove`. A caller that
passes the same Java array as input and output aliases the ranges through the
bridge; flag any new in-place transform path.
