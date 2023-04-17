
;
; AES Key scheduler implementation in assembly
; Based upon Intel Example from the
; "Intel® Advanced Encryption Standard (AES) New Instructions Set" whitepaper
; SysV abi

global _schedule_128
global _schedule_192
global _schedule_256

global _inv_128
global _inv_192
global _inv_256

%define xmm1 xmm8
%define xmm2 xmm9
%define xmm3 xmm10
%define xmm4 xmm11
%define xmm5 xmm12
%define xmm6 xmm13

%define rsi rsi
%define rdi rdi

SECTION .text
align 16
;
; extern void _schedule_128(uint8_t *key (rdi), __m128i *roundKeys (rsi) );
;
_schedule_128:
     movdqu xmm1,[rdi] ; rdi = user key
     movdqu [rsi],xmm1 ; rsi = key schedule
ASSISTS:
     aeskeygenassist xmm2,xmm1,1;   $1, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu  [16+rsi],xmm1; 16(rsi),xmm1,
     aeskeygenassist xmm2,xmm1,2;  $2, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [32+rsi],xmm1;   %xmm1, 32(%rsi)
     aeskeygenassist  xmm2,xmm1,4;  $4, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [48+rsi],xmm1;   %xmm1, 48(%rsi)
     aeskeygenassist xmm2,xmm1,8;  $8, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [64+rsi],xmm1;   %xmm1, 64(%rsi)
     aeskeygenassist xmm2,xmm1,16;   $16, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [80+rsi],xmm1;  %xmm1, 80(%rsi)
     aeskeygenassist xmm2,xmm1, 32;   $32, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu  [96+rsi],xmm1;   %xmm1, 96(%rsi)
     aeskeygenassist xmm2,xmm1,64;   $64, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [112+rsi],xmm1;    %xmm1, 112(%rsi)
     aeskeygenassist  xmm2,xmm1,0x80 ;   $0x80, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu  [128+rsi],xmm1;   %xmm1, 128(%rsi)
     aeskeygenassist  xmm2,xmm1, 0x1b;   $0x1b, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu [144+rsi],xmm1;   %xmm1, 144(%rsi)
     aeskeygenassist  xmm2,xmm1,0x36;   $0x36, %xmm1, %xmm2
     call PREPARE_ROUNDKEY_128
     movdqu  [160+rsi],xmm1;   %xmm1, 160(%rsi)

     pxor xmm1,xmm1
     pxor xmm2,xmm2
     pxor xmm3,xmm3
     ret

PREPARE_ROUNDKEY_128:
    pshufd xmm2,xmm2,255;   $255, %xmm2, %xmm2
    movdqu xmm3,xmm1;    %xmm1, %xmm3
    pslldq xmm3,4;   $4, %xmm3
    pxor xmm1,xmm3;  %xmm3, %xmm1
    pslldq xmm3,4;   $4, %xmm3
    pxor xmm1,xmm3;  %xmm3, %xmm1
    pslldq xmm3,4;   $4, %xmm3
    pxor xmm1,xmm3;  %xmm3, %xmm1
    pxor xmm1,xmm2;  %xmm2, %xmm1
    ret

;
; extern void _schedule_192(uint8_t *key (rdi), __m128i *roundKeys (rsi) );
; **** Key must be within a 32 byte block ****
;
align 16
_schedule_192:
    movdqu xmm1,[rdi];  (%rdi), %xmm1 rdi = user key
    movdqu xmm3,[16+rdi];  16(%rdi), %xmm3 rsi = key schedule
    movdqu [rsi],xmm1;   %xmm1, (%rsi)
    movdqu xmm5,xmm3;  %xmm3, %xmm5

    aeskeygenassist xmm2,xmm3,0x01;   $0x1, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    shufpd  xmm5,xmm1,0;   $0, %xmm1, %xmm5
    movdqu  [16+rsi],xmm5;   %xmm5, 16(%rsi)
    movdqu xmm6,xmm1;   %xmm1, %xmm6
    shufpd xmm6,xmm3,1;   $1, %xmm3, %xmm6
    movdqu [32+rsi],xmm6;   %xmm6, 32(%rsi)

    aeskeygenassist xmm2,xmm3,0x02;   $0x2, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    movdqu [48+rsi],xmm1;  %xmm1, 48(%rsi)
    movdqu xmm5,xmm3;   %xmm3, %xmm5

    aeskeygenassist  xmm2,xmm3,0x04;  $0x4, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    shufpd xmm5,xmm1,0;   $0, %xmm1, %xmm5
    movdqu [64+rsi],xmm5;   %xmm5, 64(%rsi)
    movdqu xmm6,xmm1;   %xmm1, %xmm6
    shufpd xmm6,xmm3,1;  $1, %xmm3, %xmm6
    movdqu [80+rsi],xmm6;  %xmm6, 80(%rsi)

    aeskeygenassist xmm2,xmm3,0x08;  $0x8, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    movdqu [96+rsi],xmm1;   %xmm1, 96(%rsi)
    movdqu xmm5,xmm3; %xmm3, %xmm5

    aeskeygenassist xmm2,xmm3,0x10;  $0x10, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    shufpd xmm5,xmm1,0;   $0, %xmm1, %xmm5
    movdqu [112+rsi],xmm5;   %xmm5, 112(%rsi)
    movdqu xmm6,xmm1;  %xmm1, %xmm6
    shufpd xmm6,xmm3,1;  $1, %xmm3, %xmm6
    movdqu [128+rsi],xmm6;    %xmm6, 128(%rsi)

    aeskeygenassist xmm2,xmm3,0x20;  $0x20, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    movdqu  [144+rsi],xmm1;  %xmm1, 144(%rsi)
    movdqu xmm5,xmm3;   %xmm3, %xmm5

    aeskeygenassist  xmm2,xmm3,0x40;  $0x40, %xmm3, %xmm2

    call PREPARE_ROUNDKEY_192
    shufpd xmm5,xmm1,0;  $0, %xmm1, %xmm5
    movdqu [160+rsi],xmm5;   %xmm5, 160(%rsi)
    movdqu xmm6,xmm1;  %xmm1, %xmm6
    shufpd xmm6,xmm3,1;  $1, %xmm3, %xmm6
    movdqu [176+rsi],xmm6;   %xmm6, 176(%rsi)

    aeskeygenassist xmm2,xmm3,0x80; $0x80, %xmm3, %xmm2
    call PREPARE_ROUNDKEY_192
    movdqu [192+rsi],xmm1;  %xmm1, 192(%rsi)

    pxor xmm1,xmm1
    pxor xmm2,xmm2
    pxor xmm3,xmm3
    pxor xmm4,xmm4
    pxor xmm5,xmm5
    pxor xmm6,xmm6
    ret


PREPARE_ROUNDKEY_192:
    pshufd xmm2,xmm2,0x55;  $0x55, %xmm2, %xmm2
    movdqu xmm4,xmm1;  %xmm1, %xmm4
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm1,xmm4;   %xmm4, %xmm1
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm1,xmm4;   %xmm4, %xmm1
    pslldq xmm4,4;   $4, %xmm4
    pxor xmm1, xmm4;   %xmm4, %xmm1
    pxor xmm1,xmm2;  %xmm2, %xmm1
    pshufd xmm2,xmm1,0xFF;  $0xff, %xmm1, %xmm2
    movdqu xmm4,xmm3;  %xmm3, %xmm4
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm3,xmm4; %xmm4, %xmm3
    pxor xmm3,xmm2;  %xmm2, %xmm3
    ret

;
; extern void _schedule_192(uint8_t *key (rdi), __m128i *roundKeys (rsi) );
;
align 16
_schedule_256:
    movdqu xmm1, [rdi]; (%rdi), %xmm1
    movdqu xmm3,[rdi+16];  16(%rdi), %xmm3
    movdqu [rsi],xmm1; %xmm1, (%rsi)
    movdqu [rsi+16],xmm3;  %xmm3, 16(%rsi)

    aeskeygenassist  xmm2,xmm3,1;  $0x1, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [32+rsi],xmm1;   %xmm1, 32(%rsi)
    aeskeygenassist xmm2,xmm1,0;   $0x0, %xmm1, %xmm2
    call MAKE_RK256_b
    movdqu [48+rsi],xmm3;  %xmm3, 48(%rsi)
    aeskeygenassist xmm2,xmm3,0x02;   $0x2, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [64+rsi],xmm1;  %xmm1, 64(%rsi)
    aeskeygenassist xmm2,xmm1,0x00;  $0x0, %xmm1, %xmm2
    call MAKE_RK256_b
    movdqu [80+rsi],xmm3;   %xmm3, 80(%rsi)
    aeskeygenassist xmm2,xmm3,0x04;   $0x4, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [96+rsi], xmm1;   %xmm1, 96(%rsi)
    aeskeygenassist  xmm2,xmm1,0;  $0x0, %xmm1, %xmm2

    call MAKE_RK256_b
    movdqu [112+rsi],xmm3;  %xmm3, 112(%rsi)
    aeskeygenassist  xmm2,xmm3,8;  $0x8, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [128+rsi],xmm1;  %xmm1, 128(%rsi)
    aeskeygenassist xmm2,xmm1,0;   $0x0, %xmm1, %xmm2
    call MAKE_RK256_b
    movdqu  [144+rsi], xmm3;  %xmm3, 144(%rsi)
    aeskeygenassist xmm2,xmm3,0x10;   $0x10, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu  [160+rsi],xmm1;   %xmm1, 160(%rsi)
    aeskeygenassist xmm2,xmm1,0;   $0x0, %xmm1, %xmm2
    call MAKE_RK256_b
    movdqu [176+rsi],xmm3;  %xmm3, 176(%rsi)
    aeskeygenassist  xmm2,xmm3,0x20;    $0x20, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [192+rsi],xmm1;   %xmm1, 192(%rsi)
    aeskeygenassist xmm2,xmm1,0;   $0x0, %xmm1, %xmm2
    call MAKE_RK256_b
    movdqu [208+rsi],xmm3;   %xmm3, 208(%rsi)
    aeskeygenassist xmm2,xmm3,0x40;   $0x40, %xmm3, %xmm2
    call MAKE_RK256_a
    movdqu [224+rsi], xmm1;  %xmm1, 224(%rsi)

    pxor xmm1,xmm1
    pxor xmm2,xmm2
    pxor xmm3,xmm3
    pxor xmm4,xmm4
    ret

MAKE_RK256_a:
    pshufd xmm2,xmm2,0xFF;   $0xff, %xmm2, %xmm2
    movdqu xmm4,xmm1;   %xmm1, %xmm4
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm1,xmm4;   %xmm4, %xmm1
    pslldq xmm4,4;   $4, %xmm4
    pxor xmm1,xmm4;   %xmm4, %xmm1
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm1,xmm4; %xmm4, %xmm1
    pxor xmm1,xmm2; %xmm2, %xmm1
    ret

MAKE_RK256_b:
    pshufd xmm2,xmm2,0xaa;  $0xaa, %xmm2, %xmm2
    movdqu xmm4,xmm3;   %xmm3, %xmm4
    pslldq xmm4,4;  $4, %xmm4
    pxor xmm3,xmm4;   %xmm4, %xmm3
    pslldq  xmm4,4;  $4, %xmm4
    pxor xmm3,xmm4;  %xmm4, %xmm3
    pslldq xmm4,4;   $4, %xmm4
    pxor xmm3,xmm4;  %xmm4, %xmm3
    pxor xmm3,xmm2;  %xmm2, %xmm3
    ret

;
; extern void _inv_256(__m128i *roundKeys (rdi) );
;
align 16
_inv_256:
   movdqu xmm1,[14*16+rdi]
   movdqu xmm2,[0*16+rdi]
   movdqu [0*16+rdi],xmm1
   movdqu [14*16+rdi],xmm2

   movdqu xmm1,[13*16+rdi]
   movdqu xmm2,[1*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [1*16+rdi],xmm1
   movdqu [13*16+rdi],xmm2

   movdqu xmm1,[12*16+rdi]
   movdqu xmm2,[2*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [2*16+rdi],xmm1
   movdqu [12*16+rdi],xmm2

   movdqu xmm1,[11*16+rdi]
   movdqu xmm2,[3*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [3*16+rdi],xmm1
   movdqu [11*16+rdi],xmm2

   movdqu xmm1,[10*16+rdi]
   movdqu xmm2,[4*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [4*16+rdi],xmm1
   movdqu [10*16+rdi],xmm2

   movdqu xmm1,[9*16+rdi]
   movdqu xmm2,[5*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [5*16+rdi],xmm1
   movdqu [9*16+rdi],xmm2
   movdqu xmm1,[8*16+rdi]

   movdqu xmm2,[6*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [6*16+rdi],xmm1
   movdqu [8*16+rdi],xmm2

   movdqu xmm1,[7*16+rdi]
   aesimc xmm1,xmm1
   movdqu [7*16+rdi],xmm1

   pxor xmm1,xmm1
   pxor xmm2,xmm2
ret ; inv_256


align 16
_inv_192:
  movdqu xmm1,[12*16+rdi]
   movdqu xmm2,[0*16+rdi]
   movdqu [0*16+rdi],xmm1
   movdqu [12*16+rdi],xmm2

   movdqu xmm1,[11*16+rdi]
   movdqu xmm2,[1*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [1*16+rdi],xmm1
   movdqu [11*16+rdi],xmm2

   movdqu xmm1,[10*16+rdi]
   movdqu xmm2,[2*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [2*16+rdi],xmm1
   movdqu [10*16+rdi],xmm2

   movdqu xmm1,[9*16+rdi]
   movdqu xmm2,[3*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [3*16+rdi],xmm1
   movdqu [9*16+rdi],xmm2

   movdqu xmm1,[8*16+rdi]
   movdqu xmm2,[4*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [4*16+rdi],xmm1
   movdqu [8*16+rdi],xmm2

   movdqu xmm1,[7*16+rdi]
   movdqu xmm2,[5*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [5*16+rdi],xmm1
   movdqu [7*16+rdi],xmm2

   movdqu xmm1,[6*16+rdi]
   aesimc xmm1,xmm1
   movdqu [6*16+rdi],xmm1

   pxor xmm1,xmm1
   pxor xmm2,xmm2

ret ; _inv_192

align 16
_inv_128:
 movdqu xmm1,[10*16+rdi]
   movdqu xmm2,[0*16+rdi]
   movdqu [0*16+rdi],xmm1
   movdqu [10*16+rdi],xmm2

   movdqu xmm1,[9*16+rdi]
   movdqu xmm2,[1*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [1*16+rdi],xmm1
   movdqu [9*16+rdi],xmm2

   movdqu xmm1,[8*16+rdi]
   movdqu xmm2,[2*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [2*16+rdi],xmm1
   movdqu [8*16+rdi],xmm2

   movdqu xmm1,[7*16+rdi]
   movdqu xmm2,[3*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [3*16+rdi],xmm1
   movdqu [7*16+rdi],xmm2

   movdqu xmm1,[6*16+rdi]
   movdqu xmm2,[4*16+rdi]
   aesimc xmm1,xmm1
   aesimc xmm2,xmm2
   movdqu [4*16+rdi],xmm1
   movdqu [6*16+rdi],xmm2

   movdqu xmm1,[5*16+rdi]
   aesimc xmm1,xmm1
   movdqu [5*16+rdi],xmm1

   pxor xmm1,xmm1
   pxor xmm2,xmm2

ret