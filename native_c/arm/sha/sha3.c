//
//

#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include "sha3.h"
#include <stdbool.h>


static const uint64_t K[] = {
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL
};

#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

void KF1600_StatePermute(uint64_t *state) {
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    //copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < 24; round += 2) {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // print_state(BCa, BCe, BCi, BCo, BCu);

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        // print_state(Da,De,Di,Do,Du);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        // print_state(BCa, BCe, BCi, BCo, BCu);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= (uint64_t) K[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        // print_state(Eba, Ebe, Ebi, Ebo, Ebu);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        // print_state(Ega, Ege, Egi, Ego, Egu);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        // print_state(Eka, Eke, Eki, Eko, Eku);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        // print_state(Ema, Eme, Emi, Emo, Emu);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        // print_state(Esa, Ese, Esi, Eso, Esu);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // print_state(BCa, BCe, BCi, BCo, BCu);

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        // print_state(Da, De, Di, Do, Du);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= (uint64_t) K[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        // print_state(Aba, Abe, Abi, Abo, Abu);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        // print_state(Aga, Age, Agi, Ago, Agu);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        // print_state(Aka, Ake, Aki, Ako, Aku);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        // print_state(Ama, Ame, Ami, Amo, Amu);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);

        // print_state(Asa, Ase, Asi, Aso, Asu);
    }

    //copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}


void keccak_absorb_buf(sha3_ctx *ctx, uint8_t *buf, size_t rateBytes) {
    uint8_t *p = buf;
    uint8x8_t *state = (uint8x8_t *) ctx->state;
    rateBytes >>= 3;

    uint8x8_t tmp;

    while (rateBytes > 0) {
        tmp = vld1_u8(p);
        //tmp = vrev64_u8(vld1_u8(p)); // load data swap endian
        tmp = veor_u8(vld1_u8((void *) state), tmp); // eor into state
        vst1_u8((void *) state, tmp);
        state++;
        p += 8;
        rateBytes--;
    }

    KF1600_StatePermute(ctx->state);
}

sha3_ctx *sha3_create_ctx(int bitLen) {
    assert(bitLen == 224 || bitLen == 256 || bitLen == 384 || bitLen == 512);
    sha3_ctx *ptr = calloc(1, sizeof(sha3_ctx));
    assert(ptr != NULL);
    ptr->bitLen = (uint32_t) bitLen;
    ptr->rate = 1600 - ((uint32_t) bitLen << 1);
    sha3_reset(ptr);
    return ptr;
}

void sha3_free_ctx(sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(sha3_ctx));
    free(ctx);
}

void sha3_reset(sha3_ctx *ctx) {
    ctx->ident = SHA3_MAGIC;
    ctx->buf_index = 0;
    ctx->byteCount = 0;
    ctx->rate_bytes = ctx->rate >> 3;
    memset(ctx->state, 0, sizeof(uint64_t) * STATE_LEN);
    memset(ctx->buf, 0, BUF_SIZE_SHA3);
    ctx->squeezing = false;
}

void sha3_update_byte(sha3_ctx *ctx, uint8_t b) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    ctx->buf[ctx->buf_index++] = b;
    ctx->byteCount++;
    if (ctx->buf_index == rateBytes) {
        keccak_absorb_buf(ctx, ctx->buf, rateBytes);
        ctx->buf_index = 0;
    }
}

void sha3_update(sha3_ctx *ctx, uint8_t *input, size_t len) {
    assert(!ctx->squeezing);
    const size_t rateBytes = ctx->rate_bytes;
    const size_t remaining = rateBytes - ctx->buf_index;

    if (ctx->buf_index != 0) {
        const size_t toCopy = remaining > len ? len : remaining;
        memcpy(&ctx->buf[ctx->buf_index], input, toCopy);
        ctx->buf_index += toCopy;
        len -= toCopy;
        input += toCopy;
        if (ctx->buf_index == rateBytes) {
            keccak_absorb_buf(ctx, ctx->buf, rateBytes);
            ctx->buf_index = 0;
        }
    }

    while (len >= rateBytes) {
        keccak_absorb_buf(ctx, input, rateBytes);
        input += rateBytes;
        len -= rateBytes;
    }

    if (len > 0) {
        memcpy(ctx->buf, input, len);
        ctx->buf_index += len;
        if (ctx->buf_index == rateBytes) {
            keccak_absorb_buf(ctx, ctx->buf, rateBytes);
            ctx->buf_index = 0;
        }
    }

    ctx->byteCount += len;
}

void sha3_digest(sha3_ctx *ctx, uint8_t *output) {
    size_t rateBytes = ctx->rate_bytes;
    const size_t toClear = rateBytes - ctx->buf_index;

    // Padding will be set up inside the buffer so
    // we need to zero out any unused buffer first.
    // TODO add padding to state directly.
    memset(ctx->buf + ctx->buf_index, 0, toClear); // clear to end of buffer
    switch (ctx->bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            ctx->buf[ctx->buf_index] = 0x06;
            break;

    }

    ctx->buf[rateBytes - 1] |= 128;

    uint8_t *p = ctx->buf;
    uint8x8_t tmp;
    uint8x8_t *state = (uint8x8_t *) ctx->state;
    for (int i = 0; i < rateBytes >> 3; i++) {
        tmp = vld1_u8(p);
        tmp = veor_u8(vld1_u8((void *) state), tmp); // eor into state
        vst1_u8((void *) state, tmp);
        state++;
        p += 8;
    }

    ctx->squeezing = true;

    uint8x8_t *s = (uint8x8_t *) ctx->state;
    KF1600_StatePermute(ctx->state);

    memcpy(output, ctx->state, ctx->bitLen / 8);
}

uint32_t sha3_getSize(sha3_ctx *ctx) {
    return ctx->bitLen >> 3;
}

uint32_t sha3_getByteLen(sha3_ctx *ctx) {
    return ctx->rate >> 3;
}

bool sha3_restoreFullState(sha3_ctx *ctx, const uint8_t *oldState) {
    sha3_ctx newState;
    memcpy(&newState, oldState, sizeof(sha3_ctx));

    if (newState.ident != SHA3_MAGIC) {
        return false;
    }

    switch (newState.bitLen) {
        case 224:
        case 256:
        case 384:
        case 512:
            break;
        default:
            return false;
    }

    // Recalculate these
    newState.rate = 1600 - ((uint32_t) newState.bitLen << 1);
    newState.rate_bytes = newState.rate >> 3;

    if (newState.buf_index >= BUF_SIZE_SHA3) {
        return false;
    }

    *ctx = newState;

    return true;
}

size_t sha3_encodeFullState(const sha3_ctx *ctx, uint8_t *output) {
    memcpy(output, ctx, sizeof(sha3_ctx));
    return sizeof(sha3_ctx);
}