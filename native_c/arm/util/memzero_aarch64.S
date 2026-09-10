//
// memzero -- secure buffer erase.  Hand written AArch64 (AAPCS64) assembly.
//
//   void memzero(void *const pnt, const size_t len);      x0 = pnt, x1 = len
//
// The observable contract:
//
//   * every byte of [pnt, pnt+len) is set to 0x00;
//   * NO byte outside [pnt, pnt+len) is written.  Callers pass sub ranges of
//     larger, still live buffers -- e.g. arm/sha/shake.c does
//     memzero(buf + ctx->buf_u8_index, toClear) -- so a store one byte past
//     len corrupts live data.  Every tail here is an *overlapping* store that
//     re-zeroes bytes already inside the range, never one byte beyond it;
//   * len == 0 writes nothing and never dereferences pnt;
//   * pnt carries no alignment requirement (AArch64 normal-memory stores are
//     unaligned-safe, and Linux user space maps the heap as normal memory).
//
// Why assembly.
//
// A C implementation can keep its erasing stores alive only by hints to the
// optimiser -- a volatile qualified pointer variable, a memory clobber --
// and a NEON store body needs a cast that drops volatile from the pointee,
// which leaves ordinary stores the optimiser merely cannot yet track.  An
// LTO build, or a compiler that reasons harder about the provenance of a
// volatile-loaded pointer, is free to prove the buffer dead and delete them.
// Code the C compiler never parses cannot be deleted by the C compiler.
//
// Instruction floor.
//
// Everything here is baseline ARMv8-A plus NEON, the same floor as the rest
// of the neon-le variant (-march=armv8-a+crypto, Graviton 1/2 / Neoverse-N1
// class).  "stp q0, q0" is a baseline SIMD&FP store pair, and the BTI landing
// pad is written as "hint #34", which the architecture defines as a NOP on
// every core below ARMv8.5, so the file assembles and runs at the floor.
//
// Register use.  One line for each register.  "in" marks a register whose
// value arrives from the caller, "scratch" one this routine invents.
//
//   x0      in       pnt -- base address of the region to erase.  AAPCS64
//                    argument 1.  Never modified; every store is based on it,
//                    so the original pointer stays available to the last store.
//   x1      in       len -- byte count to erase.  AAPCS64 argument 2.
//                    Never modified; every tier compares against it and the
//                    tail stores address off the end pointer derived from it.
//   x2      scratch  Two distinct jobs, one for each path.
//                    Vector path: the moving store cursor, walked from x0
//                    upward in 32 byte steps until it reaches x3.
//                    Small paths: the end pointer pnt + len, so each tail
//                    store is [x2 - width], which keeps it inside the range.
//   x3      scratch  Address of the FINAL full 32 byte block, computed once
//                    as pnt + len - 32.  Doubles as the loop bound and as the
//                    destination of the overlapping tail store.  Vector loop
//                    only; unused on the smaller paths.
//   v0/q0   scratch  All-zero store source for the 16 byte and wider stores.
//                    The 8/4/2/1 byte stores use xzr/wzr and need no register
//                    at all.
//
// Nothing secret is ever loaded, so no register can carry a secret out.  v0
// holds zero on return and x2/x3 hold addresses; all are safe to leave live.
// The function is a leaf and touches no stack, so it is trivially compatible
// with a shadow call stack and with PAC-signed callers.
//

    .text
    .global memzero
    .type   memzero, %function

    .balign 16
memzero:
    hint    #34                         // bti c: BTI landing pad, NOP below ARMv8.5
    cbz     x1, .Lret                   // len == 0: touch nothing at all

    cmp     x1, #32
    b.lo    .Lbelow32

    //
    // ---- 32 bytes and up: stp q0, q0 writes 32 bytes per iteration -------
    //
    movi    v0.16b, #0
    add     x3, x0, x1
    sub     x3, x3, #32                 // start of the final 32 byte block
    mov     x2, x0
    .balign 16                          // keep the hot loop inside one fetch window
.Lloop32:
    stp     q0, q0, [x2]
    add     x2, x2, #32
    cmp     x2, x3
    b.lo    .Lloop32
    stp     q0, q0, [x3]                // overlapping tail, still inside range
    ret

.Lbelow32:
    add     x2, x0, x1                  // end pointer for every overlapping tail
    cmp     x1, #16
    b.lo    .Lbelow16
    //
    // 16..31 -- two overlapping 16 byte stores cover it with no loop.
    //
    movi    v0.16b, #0
    str     q0, [x0]
    stur    q0, [x2, #-16]
    ret

    //
    // ---- 1..15 bytes, scalar ---------------------------------------------
    //
    // Each size class is two overlapping stores of the widest type that
    // fits, so at most two stores run and neither can leave the range.  The
    // zero source is the architectural zero register.
    //
.Lbelow16:
    cmp     x1, #8
    b.lo    .Lbelow8
    str     xzr, [x0]                   // 8..15
    stur    xzr, [x2, #-8]
    ret

.Lbelow8:
    cmp     x1, #4
    b.lo    .Lbelow4
    str     wzr, [x0]                   // 4..7
    stur    wzr, [x2, #-4]
    ret

.Lbelow4:
    cmp     x1, #2
    b.lo    .Lone
    strh    wzr, [x0]                   // 2..3
    sturh   wzr, [x2, #-2]
    ret

.Lone:
    strb    wzr, [x0]                   // exactly 1
.Lret:
    ret

    .size   memzero, . - memzero

//
// Mark the object non executable stack.  Without this the assembler emits no
// .note.GNU-stack section, the linker conservatively marks the whole shared
// library RWE, and the JVM prints a stack guard warning.  Every assembly
// source must declare this section.
//
    .section .note.GNU-stack, "", %progbits

//
// Mark the object as compatible with Branch Target Identification.  The GNU
// property is AND-ed across every input object, so every assembly source must
// carry it or the shared library ships with no BTI marking once the C objects
// are built with -mbranch-protection.  BTI requires a landing pad at every
// indirectly reachable entry point, which includes every exported function:
// intra-library calls to exported symbols go through the PLT, and a PLT jump
// is an indirect branch.  The pad is the hint #34 at the entry above.  PAC is
// deliberately not claimed: this function signs no return address.
//
    .section .note.gnu.property, "a", %note
    .balign 8
    .word   4                           // n_namesz  = sizeof "GNU"
    .word   16                          // n_descsz
    .word   5                           // n_type    = NT_GNU_PROPERTY_TYPE_0
    .asciz  "GNU"
    .word   0xc0000000                  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
    .word   4                           // pr_datasz
    .word   1                           // GNU_PROPERTY_AARCH64_FEATURE_1_BTI
    .word   0                           // pad to 8 byte alignment
