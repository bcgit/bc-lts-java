;
; memzero -- secure buffer erase.  Hand written SysV AMD64 assembly.
;
;   void memzero(void *const pnt, const size_t len);      rdi = pnt, rsi = len
;
; The observable contract:
;
;   * every byte of [pnt, pnt+len) is set to 0x00;
;   * NO byte outside [pnt, pnt+len) is written.  Callers pass sub ranges of
;     larger, still live buffers -- e.g. intel/sha/shake.c does
;     memzero(buf + ctx->buf_u8_index, toClear) -- so a store one byte past
;     len corrupts live data.  Every tail here is an *overlapping* store that
;     re-zeroes bytes already inside the range, never one byte beyond it;
;   * len == 0 writes nothing and never dereferences pnt;
;   * pnt carries no alignment requirement (all stores are unaligned forms).
;
; Why assembly.
;
; A C implementation can keep its erasing stores alive only by hints to the
; optimiser -- a volatile qualified pointer variable, a memory clobber -- and
; a SIMD store body needs a cast that drops volatile from the pointee, which
; leaves ordinary stores the optimiser merely cannot yet track.  An LTO
; build, or a compiler that reasons harder about the provenance of a
; volatile-loaded pointer, is free to prove the buffer dead and delete them.
; Code the C compiler never parses cannot be deleted by the C compiler.
;
; Register use.  One line for each register.  "in" marks a register whose
; value arrives from the caller, "scratch" one this routine invents.
;
;   rdi     in       pnt -- base address of the region to erase.  SysV integer
;                    argument 1.  Never modified; every store is based on it,
;                    so the original pointer stays available to the last store.
;   rsi     in       len -- byte count to erase.  SysV integer argument 2.
;                    Never modified; every tier compares against it and the
;                    tail stores address off it as [rdi + rsi - width].
;   rax     scratch  Two distinct jobs, one for each path.
;                    Vector path: the moving store cursor, walked from rdi
;                    upward in width sized steps until it reaches rcx.
;                    Scalar path (1..15 bytes): the zero source, set by
;                    "xor eax, eax", used as rax / eax / ax / al so one
;                    register covers the 8, 4, 2 and 1 byte stores.
;   rcx     scratch  Address of the FINAL full width block, computed once as
;                    [rdi + rsi - width].  Doubles as the loop bound and as
;                    the destination of the overlapping tail store, which is
;                    what keeps every write inside [pnt, pnt+len).
;                    Vector loop tiers only; unused on the scalar path.
;   zmm0    scratch  All-zero store source, 512 bit tier only (BC_VAESF).
;   ymm0    scratch  All-zero store source, 256 bit tier and the 32..63 byte
;                    case of the 512 bit tier.
;   xmm0    scratch  All-zero store source, 128 bit tier and the 16..31 byte
;                    case of the wider tiers.
;
; Nothing secret is ever loaded, so no register can carry a secret out. The
; vector register holds zero on return and rax holds either zero or an
; address; both are safe to leave live.
;
; The tier split (BC_VAESF / BC_VAES / neither) follows the variant build:
; the same -DBC_* flags CMake feeds the C compiler are fed to NASM.
;

%ifdef BC_VAESF
    %define BC_MZ_TIER 512
%elifdef BC_VAES
    %define BC_MZ_TIER 256
%else
    %define BC_MZ_TIER 128
%endif

global memzero

SECTION .text

align 16
memzero:
    endbr64

    test    rsi, rsi
    je      .ret_clean                  ; len == 0: touch nothing at all

%if BC_MZ_TIER >= 512
    ;
    ; ---- 512 bit tier ------------------------------------------------
    ;
    cmp     rsi, 64
    jb      .below64

    vpxorq  zmm0, zmm0, zmm0
    lea     rcx, [rdi + rsi - 64]       ; start of the final 64 byte block
    mov     rax, rdi
align 16                                ; see the alignment note at .loop128
.loop512:
    vmovdqu64 [rax], zmm0
    add     rax, 64
    cmp     rax, rcx
    jb      .loop512
    vmovdqu64 [rcx], zmm0               ; overlapping tail, still inside range
    jmp     .ret

.below64:
    cmp     rsi, 32
    jb      .below32
    ;
    ; 32..63 -- two overlapping 32 byte stores cover it with no loop.
    ;
    vpxor   ymm0, ymm0, ymm0
    vmovdqu [rdi], ymm0
    vmovdqu [rdi + rsi - 32], ymm0
    jmp     .ret

%elif BC_MZ_TIER >= 256
    ;
    ; ---- 256 bit tier ------------------------------------------------
    ;
    cmp     rsi, 32
    jb      .below32

    vpxor   ymm0, ymm0, ymm0
    lea     rcx, [rdi + rsi - 32]       ; start of the final 32 byte block
    mov     rax, rdi
align 16                                ; see the alignment note at .loop128
.loop256:
    vmovdqu [rax], ymm0
    add     rax, 32
    cmp     rax, rcx
    jb      .loop256
    vmovdqu [rcx], ymm0                 ; overlapping tail, still inside range
    jmp     .ret

%else
    ;
    ; ---- 128 bit tier ------------------------------------------------
    ;
    cmp     rsi, 16
    jb      .below16

    vpxor   xmm0, xmm0, xmm0
    lea     rcx, [rdi + rsi - 16]       ; start of the final 16 byte block
    mov     rax, rdi
    ;
    ; Align the hot loop.  The body is 13 bytes, so at an arbitrary link
    ; address it can straddle a 32 byte instruction fetch boundary.  Measured
    ; on Tiger Lake, the unaligned form cost up to 1.45x on mid sized buffers
    ; and the penalty moved with the address the linker happened to pick --
    ; the same object was fast in one executable and slow in another.  Align
    ; it so the timing is a property of the code, not of the link order.
    ;
align 16
.loop128:
    vmovdqu [rax], xmm0
    add     rax, 16
    cmp     rax, rcx
    jb      .loop128
    vmovdqu [rcx], xmm0                 ; overlapping tail, still inside range
    jmp     .ret
%endif

%if BC_MZ_TIER >= 256
.below32:
    cmp     rsi, 16
    jb      .below16
    ;
    ; 16..31 -- two overlapping 16 byte stores.
    ;
    vpxor   xmm0, xmm0, xmm0
    vmovdqu [rdi], xmm0
    vmovdqu [rdi + rsi - 16], xmm0
    jmp     .ret
%endif

    ;
    ; ---- 1..15 bytes, scalar -------------------------------------------
    ;
    ; Each size class is two overlapping stores of the widest type that
    ; fits, so at most two stores run and neither can leave the range.
    ;
.below16:
    xor     eax, eax

    cmp     rsi, 8
    jb      .below8
    mov     [rdi], rax                  ; 8..15
    mov     [rdi + rsi - 8], rax
    jmp     .ret

.below8:
    cmp     rsi, 4
    jb      .below4
    mov     [rdi], eax                  ; 4..7
    mov     [rdi + rsi - 4], eax
    jmp     .ret

.below4:
    cmp     rsi, 2
    jb      .one
    mov     [rdi], ax                   ; 2..3
    mov     [rdi + rsi - 2], ax
    jmp     .ret

.one:
    mov     [rdi], al                   ; exactly 1

.ret:
%if BC_MZ_TIER >= 256
    ;
    ; Leave no dirty upper vector state behind.  Callers include legacy SSE
    ; encoded code (intel/common_sysV.asm uses movdqu / pxor), which pays the
    ; AVX-SSE transition penalty on every instruction until the state is
    ; cleared.  The C original relied on the compiler inserting this; here it
    ; is explicit, and it also guarantees zmm0/ymm0 carry nothing outward.
    ;
    vzeroupper
%endif
.ret_clean:
    ret

;
; Mark the object non executable stack.  Without this NASM emits no
; .note.GNU-stack section, the linker conservatively marks the whole shared
; library RWE, and the JVM prints a stack guard warning.  Every assembly
; source must declare this section.
;
SECTION .note.GNU-stack noalloc noexec nowrite progbits

;
; Mark the object as supporting Intel CET (IBT + SHSTK).  The GNU property is
; AND-ed across every input object, so every assembly source must carry it
; (the C objects get it from the compiler) or the shared library ships with
; no CET marking at all.  IBT requires an endbr64 at every indirectly
; reachable entry point, which includes every exported function: intra-library
; calls to exported symbols go through the PLT, and a PLT jump is an indirect
; branch.
;
SECTION .note.gnu.property note alloc noexec align=8
    dd      4                           ; n_namesz  = sizeof "GNU"
    dd      16                          ; n_descsz
    dd      5                           ; n_type    = NT_GNU_PROPERTY_TYPE_0
    db      "GNU", 0
    dd      0xc0000002                  ; GNU_PROPERTY_X86_FEATURE_1_AND
    dd      4                           ; pr_datasz
    dd      3                           ; GNU_PROPERTY_X86_FEATURE_1_IBT
                                        ;   | GNU_PROPERTY_X86_FEATURE_1_SHSTK
    dd      0                           ; pad to 8 byte alignment
