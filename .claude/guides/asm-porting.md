# C to assembly porting guide

How to replace a C function in `native_c/` with machine written assembly, and how
to prove the replacement is correct. This is a standalone reference guide; it is
not auto-loaded (LTS CLAUDE.md does not import guides).

Every rule below comes from the `memzero` port, the first function moved to
assembly in this tree (`intel/util/memzero_sysV.asm` and
`arm/util/memzero_aarch64.S`). Where a rule exists because something went wrong,
the guide says so. The same port was done on `bc-fips`; keep the two trees in
step. Read the native-acceleration section of the project CLAUDE.md first; this
guide adds to it and does not replace it.

## Defined terms

STE does not approve these words. They are necessary in this document.

| Term | Meaning |
|---|---|
| AAPCS64 | The AArch64 procedure call standard. The calling convention on ARM Linux. |
| ABI | Application binary interface. The register and stack contract between functions. |
| BTI | Branch Target Identification. The AArch64 feature that needs a landing pad at each indirect branch target. |
| CET | Control-flow Enforcement Technology. Intel hardware control flow protection. |
| excursion | A write outside the range the caller asked for, measured in bytes. |
| GAS | The GNU assembler. It assembles `.S` files through the gcc driver. |
| IBT | Indirect Branch Tracking. The CET feature that needs an `endbr64` at each indirect branch target. |
| LTO | Link time optimisation. The compiler optimises across translation units at link time. |
| mutant | A copy of the assembly with one deliberate bug in it. |
| mutation test | A run of the harness against a mutant. The harness must fail the mutant. |
| NASM | The Netwide Assembler. The Intel assembler for this tree. |
| PAC | Pointer Authentication. The AArch64 feature that signs return addresses. |
| SHSTK | Shadow Stack. The CET feature that keeps a protected copy of return addresses. |
| SysV | The System V AMD64 ABI. The calling convention on Intel Linux. |
| tier | One Intel CPU feature level: `avx`, `vaes` or `vaesf`. |
| VEX | The instruction encoding that AVX uses. |

## 1. Choose the function

Port a function only when the C version cannot give a guarantee that machine
code can. Speed alone is not a reason. The compiler beats machine written
assembly on most code, and it re-tunes its output for each new target.

Good reasons to port:

- The C stays correct only while the optimiser holds back. `memzero`
  is the model case. Its erase must survive, but the C only asks the optimiser
  to keep it.
- The code must be constant time, and the C gives no such guarantee.
- The C emits an instruction sequence that leaks through a side channel.

Bad reasons to port:

- The assembly looks faster. Measure the C first.
- The function is complex. Complex functions are the worst candidates.

Prefer a leaf function with a narrow contract. `memzero` has two parameters,
no state, no allocation and no error path. A function with error paths, JNI
calls or a lifecycle struct is a poor first target.

## 2. Read the compiler output first

Disassemble the C at the exact build flags before any assembly is written.
The compiler is the reference implementation.

```bash
objdump -d --no-show-raw-insn -Mintel CMakeFiles/bc-lts-avx.dir/intel/util/util.c.o
```

Do this for **every** tier. The `memzero` disassembly showed facts that
the source alone did not:

- the base `avx` tier already emits VEX encodings, so the assembly may use
  them and adds no new CPU requirement;
- the compiler inserts `vzeroupper` on the `vaes` and `vaesf` tiers;
- the C keeps the erasing store live only through a volatile pointer and a
  memory clobber, which a harder optimiser may still defeat.

Record the instruction count. It is the performance target.

When the C version was already deleted (see section 3), recover it from git
history for the comparison build. Name the commit that removed
`native_c/intel/util/util.c` and the `arm/util` equivalent. In this tree that
deletion is part of the memzero-port change; until it is committed, `git show
HEAD:native_c/intel/util/util.c` still shows the C original.

## 3. Match the tier structure, then delete the C

CMake passes the same `-DBC_*` flags to NASM as to the C compiler. The targets
declare them with `target_compile_definitions`, which applies to every
language. Check `CMakeFiles/<target>.dir/flags.make` to confirm. Mirror the C `#ifdef` ladder with a NASM `%ifdef` ladder, so one file
covers all tiers.

```nasm
%ifdef BC_VAESF
    %define BC_MZ_TIER 512
%elifdef BC_VAES
    %define BC_MZ_TIER 256
%else
    %define BC_MZ_TIER 128
%endif
```

Prove that the tier defines reached the assembler, on the built libraries:

```bash
objdump -d --disassemble=memzero <bc-lts-avx.so>    # must use xmm
objdump -d --disassemble=memzero <bc-lts-vaes.so>   # must use ymm
objdump -d --disassemble=memzero <bc-lts-vaesf.so>  # must use zmm
```

One latent hazard to record in the file: the base tier may use VEX encodings
only because the lowest Linux tier is `avx`. A plain SSE target does not exist
on Linux today (`SSE_OPTIONS` is set but no `sse` library is added). If one is
ever added, the base tier needs SSE encodings (`pxor` / `movdqu`) or a fourth
tier. Without that it faults on a CPU without AVX.

**Delete the C implementation once the proof in section 8 has run.**

The tree keeps no C fallback and no A/B build option. A C body that can be
built back in is an erase that a future flag change can re-select without
notice. The point of the port is that the C compiler never sees the code.
The equivalence reference comes from git history from then on. Keep the
declaration and any shared macros in `util.h`; only the `.c` body goes.

## 4. Object and ABI rules — Intel

Every new assembly file must satisfy all the rules below.

- **Emit `.note.GNU-stack`.** Without it the linker marks the whole shared
  library as executable stack. `build_linux.sh` verifies the linked libraries
  with `readelf` and **fails the build** on an executable stack, so an assembly
  file that omits the section cannot ship. This replaced the old `execstack -c`
  post-processing step.
- **Emit `.note.gnu.property` with IBT and SHSTK.** The linker AND-s this
  property across all input objects. One object without it strips the CET property
  from the whole library, even though every C object carries it. Before the
  memzero port `intel/common_sysV.asm` carried no property, so the libraries
  shipped without CET; that file now carries the two sections too.
- **Start each exported function with `endbr64`.** IBT needs a landing pad at
  every indirect branch target, and every exported function is one.
  Intra-library calls to exported symbols go through the PLT, and a PLT jump
  is an indirect branch. Labels reached only by direct `call` / `jcc` need no
  pad.
- **Emit `vzeroupper` before return** if the function touches `ymm` or `zmm`.
  Callers include legacy SSE encoded assembly. Dirty upper state costs a
  penalty on every later SSE instruction.
- **Stay position independent.** NASM does not receive `-fPIC`. Use no
  absolute addresses.
- **Names are public.** LTS ships no version script, so every exported symbol,
  including a new assembly symbol, is part of the library's public symbol table.
  Choose a clear name and confirm it does not collide with an existing export.

Copy the exact section syntax from the bottom of
`intel/util/memzero_sysV.asm`; it is the canonical form, and
`intel/common_sysV.asm` carries the same two sections.

Verify on the object, not by eye:

```bash
readelf -n mz_avx.o                      # both notes must appear
readelf -SW mz_avx.o | grep GNU-stack
nm -D --defined-only <bc-lts-avx.so> | grep <symbol>
```

## 5. Object and ABI rules — ARM

The ARM side is a different assembler and a different protection scheme.

- **Write GAS syntax in a `.S` file.** NASM is Intel only. The gcc cross
  driver assembles `.S`. CMake needs `enable_language(ASM)` in the ARM branch
  (added for the memzero port), and the file listed as a normal source. No
  `ASM_OPTIONS` are needed: the file assembles at the driver default
  `-march=armv8-a`.
- **Stay on the instruction floor.** The `neon-le` variant floor is baseline
  ARMv8-A plus NEON (Graviton 1/2 / Neoverse-N1). `stp q0, q0` is a baseline
  SIMD&FP store pair and writes 32 bytes for each instruction. Anything above
  the floor belongs behind the per-service HWCAP gate (see the ARM section of
  the project CLAUDE.md and `arm/jni/services.h`), not in a common file. This
  is the same rule that keeps the always-on kernels clear of `FEAT_SHA3`
  `EOR3` on Graviton 2.
- **Write the BTI landing pad as `hint #34`, not as the `bti c` mnemonic.**
  The two encode the same instruction, but the mnemonic needs a higher
  `-march` to assemble. The hint form is a NOP below ARMv8.5 by architectural
  definition, so the file both assembles and runs at the floor.
- **Emit `.section .note.GNU-stack, "", %progbits`.** The same executable
  stack rule as Intel. `build_linux_arm.sh` does not yet carry the `readelf`
  build guard that `build_linux.sh` has. Add it there too for the same
  enforcement on the ARM library.
- **Emit the AArch64 `.note.gnu.property` with BTI only.** Claim PAC only if
  the function signs its return address; a leaf that never touches the stack
  does not. The property is AND-ed like the Intel one. The ARM C objects do
  not carry the property today (no `-mbranch-protection`), so the linked
  library has none either. The assembly note is inert until the C side opts
  in. If the C side ever opts in, do it on bc-fips and bc-lts together, so the
  two ARM libraries keep the same posture.
- **Unaligned stores are safe on normal memory.** Linux user space never sets
  the alignment check bit, and the heap is normal memory. The one class that
  always requires alignment — exclusives and atomics — has no place in a leaf
  erase function.

Copy the section syntax from the bottom of `arm/util/memzero_aarch64.S`.

## 6. Document the registers

Give a register block in the file header, one line for each register. State
which registers arrive from the caller and which the routine invents. A
reviewer cannot check register discipline against a paragraph of prose.

Verify the block against the encodings, not by eye:

```bash
objdump -d --no-show-raw-insn -Mintel mz_avx.o | sed -n '/<memzero>:/,$p' \
  | grep -oE '\b(r[a-z0-9]+|e[a-z]x|[xyz]mm[0-9]+)\b' | sort -u
```

Use `aarch64-linux-gnu-objdump` for the ARM object; the host `objdump` cannot
disassemble it.

## 7. Align every hot loop

Put `align 16` (NASM) or `.balign 16` (GAS) before each loop label. This is
the sharpest lesson of the `memzero` port.

The first version had no alignment. The same object file measured **0.69x**
against the C in one executable and **1.10x** in another. The loop body was 13
bytes. At some link addresses it straddled a 32 byte instruction fetch
boundary, and the linker chose the address. The compiler aligns loops for you;
machine written assembly gives that up.

Never accept a benchmark from a single binary. Build the harness twice, in two
separate executables. Disagreement between them means an alignment problem,
not noise.

## 8. Prove equivalence and the contract

This is the deliverable, not the assembly. The `memzero` port settled on three
harnesses, and a new port needs the same three shapes. The `memzero` set lives
in session scratch, so copy the shapes, not the files.

**(a) Contract sweep.** Sizes in steps of one across every internal width
boundary, plus larger sizes that drive many loop iterations. Start offsets
through every alignment class. Guard bands of a non-zero sentinel on both
sides, exact verify of the full extent.

**(b) Guard page proof.** `mmap` with `PROT_NONE` pages on both sides.

- One mode pins the **end** of the range against the upper trap page for every
  length: an excursion of one byte becomes a fault. The length sweep drives
  the start address through the residues.
- One mode pins the **start** against the lower page: the under-write fault.
- One mode sweeps **all 64 start residues**: a 0..15 sweep never exercises
  residues 16..63, and the 64 byte `zmm` stores see addresses mod 64.
- The degenerate input runs with the pointer **on** the trap page:
  `memzero(p, 0)` must not touch `p`.
- Size the RW window so the harness's own band writes fit at the largest
  length. An undersized window makes the harness fault on its own `memset`,
  and that fault looks exactly like an assembly bug.

**(c) Window slide with position dependent fill.**

Fill the buffer with a byte that is a function of its absolute index,
distinct across adjacent 256 byte blocks. Never use a constant fill: it cannot tell "left alone" from
"overwritten with a copy of its neighbour". Slide the target range across the
buffer, and refill before every call. Verify the **entire** buffer after each
call: zeros inside the window, the exact position byte everywhere else. This
is the net for a displaced write that lands inside the buffer.

General rules for all three:

- **Assert ground truth, not only A equals B.** Two implementations can agree
  and both be wrong. For the differential run against the C, compile the git
  history C with the symbol renamed and link both into one binary.
- **Measure the excursion, do not only detect it.** Report the count; zero is
  then a measurement.
- Run the Intel tiers natively. Run the ARM build under
  `qemu-aarch64 -L /usr/aarch64-linux-gnu` at **both** `-cpu cortex-a72` (the
  floor stand-in; the host qemu here does not know `neoverse-n1`) and `-cpu max`.
  Link harnesses against the per-variant `.so` directly; LTS exports `memzero`,
  so no symbol is hidden.

## 9. Attack the harness

A harness that has never failed proves nothing. Before you trust it, build
mutants and confirm each one fails.

Make one deliberate bug for each failure class you claim to catch:

| Mutant | Change | Expected result |
|---|---|---|
| over-write | move a tail store one byte further | fault, or excursion of 1 byte |
| under-write | move a head store one byte earlier | fault, or excursion of 1 byte |
| short write | replace a store with `nop` | content mismatch |
| dropped tail | remove the tail store of one size class | content mismatch |

`sed` over the assembly source is enough to make a mutant. Keep the mutant
commands next to the harness, so the next person can repeat the check.

One trap: a mutant may fault before it reaches the code that measures. Give
the harness a mode selector, so you can point a mutant at the mode where the
bug is measured and not merely faulted.

## 10. Integrate and test for real

The unit harnesses are not enough. Rebuild both arches and run the native
suites. `JAVA_HOME` must point to a JDK 21 for the build.

```bash
export JAVA_HOME=$LTS_JDK21
./gradlew clean cleanNative :core:compileJava -x test   # regenerate JNI headers
(cd native_c && ./build_linux.sh)                       # x86; fails on an executable stack
(cd native_c && ./build_linux_arm.sh)                   # cross-compile aarch64
./gradlew clean cleanNative withNative build testAVX -x test
./gradlew clean cleanNative withNative build testVAES -x test
./gradlew clean cleanNative withNative build testVAESF -x test
```

The per-variant tasks each force one Intel variant; the default `test` task
forces the pure-Java path and proves nothing about the assembly. The ARM
`neon-le` variant has no host task on an x86 build host. Exercise it on real
aarch64 or under `qemu`; a docker `--platform linux/arm64` run works.
`BUILD SUCCESSFUL` is not proof. Confirm `skipped=0` in the result XMLs, as a
native test that skips looks the same as one that passes. The Intel build
script verifies the stack flags itself and fails loudly.

Re-run everything after any later edit to the assembly, even a comment. Then
re-stage the file.

## 11. Checklist

- [ ] The C version cannot give the guarantee; assembly can.
- [ ] The C disassembly is read at every tier.
- [ ] The `%ifdef` ladder matches the C `#ifdef` ladder, and the built
      libraries prove it (`xmm` / `ymm` / `zmm` in the disassembly).
- [ ] The C implementation is deleted after the proof; the reference lives in
      git history.
- [ ] `.note.GNU-stack` and `.note.gnu.property` appear in `readelf -n`, on
      both arches.
- [ ] `endbr64` starts each exported Intel function; `hint #34` starts each
      exported ARM function.
- [ ] The ARM file assembles and runs at the `-cpu cortex-a72` floor.
- [ ] `vzeroupper` runs before return on any `ymm` or `zmm` path.
- [ ] Each hot loop has `align 16` / `.balign 16`.
- [ ] The register block is checked against the encodings.
- [ ] All three harness shapes run: contract sweep, guard page proof with all
      64 residues, window slide with position dependent fill.
- [ ] Excursion is measured in bytes and reported as zero.
- [ ] The degenerate length runs with the pointer on a trap page.
- [ ] Every mutant fails the harness.
- [ ] Benchmarks come from two separate executables and agree.
- [ ] The per-variant native tasks pass with `skipped=0`.
