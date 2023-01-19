//
// Created  on 7/6/2022.
//

#include <immintrin.h>
#include <cstring>

#include "AesCBCDecryptVaesF.h"

namespace intel {
    namespace cbc {


        //
        // AES CBC 128 Decryption
        //
        AesCBC128VaesFDec::AesCBC128VaesFDec() : CBC512wide() {

        }

        AesCBC128VaesFDec::~AesCBC128VaesFDec() = default;

        size_t AesCBC128VaesFDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;
            while (blocks >= 4) {
                __m512i data = _mm512_loadu_si512((__m512i *) in);

                __m512i tmp = _mm512_xor_si512(data, roundKeys[10]);

                tmp = _mm512_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm512_aesdeclast_epi128(tmp, roundKeys[0]);

                _mm512_storeu_si512((__m512i *) out, _mm512_xor_si512(
                        tmp,
                        _mm512_permutex2var_epi64(
                                data,
                                feedbackCtrl,
                                _mm512_castsi128_si512( feedback))));

                feedback = ((__m128i *) &data)[3];
                in += CBC_BLOCK_SIZE_4;
                out += CBC_BLOCK_SIZE_4;
                blocks -= 4;
            }


            auto rk256 = (__m256i *) roundKeys;
            while (blocks >= 2) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, rk256[20]);

                tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[2]);
                tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);

                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));


                //fb[0] = ((__m128i *) &data)[1];
                feedback = _mm256_extracti128_si256(data, 1);
                in += CBC_BLOCK_SIZE_2;
                out += CBC_BLOCK_SIZE_2;
                blocks -= 2;
            }

            auto *rk128 = (__m128i *) roundKeys;
            while (blocks > 0) {

                //
                // Remaining single blocks.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);

                __m128i tmp = _mm_xor_si128(data, rk128[40]);
                tmp = _mm_aesdec_si128(tmp, rk128[36]);
                tmp = _mm_aesdec_si128(tmp, rk128[32]);
                tmp = _mm_aesdec_si128(tmp, rk128[28]);
                tmp = _mm_aesdec_si128(tmp, rk128[24]);
                tmp = _mm_aesdec_si128(tmp, rk128[20]);
                tmp = _mm_aesdec_si128(tmp, rk128[16]);
                tmp = _mm_aesdec_si128(tmp, rk128[12]);
                tmp = _mm_aesdec_si128(tmp, rk128[8]);
                tmp = _mm_aesdec_si128(tmp, rk128[4]);
                tmp = _mm_aesdeclast_si128(tmp, rk128[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            return (size_t) (out - outStart);
        }


        //
        // AES CBC 192 Decryption
        //
        AesCBC192VaesFDec::AesCBC192VaesFDec() : CBC512wide() {

        }

        AesCBC192VaesFDec::~AesCBC192VaesFDec() = default;


        size_t AesCBC192VaesFDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;
            while (blocks >= 4) {
                __m512i data = _mm512_loadu_si512((__m512i *) in);

                __m512i tmp = _mm512_xor_si512(data, roundKeys[12]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[11]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[10]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm512_aesdeclast_epi128(tmp, roundKeys[0]);

                _mm512_storeu_si512((__m512i *) out, _mm512_xor_si512(
                        tmp,
                        _mm512_permutex2var_epi64(
                                data,
                                feedbackCtrl,
                                _mm512_castsi128_si512( feedback))));

                feedback = ((__m128i *) &data)[3];
                in += CBC_BLOCK_SIZE_4;
                out += CBC_BLOCK_SIZE_4;
                blocks -= 4;
            }


            auto rk256 = (__m256i *) roundKeys;
            while (blocks >= 2) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, rk256[24]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[22]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[20]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[2]);
                tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);

                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));


                //fb[0] = ((__m128i *) &data)[1];
                feedback = _mm256_extracti128_si256(data, 1);
                in += CBC_BLOCK_SIZE_2;
                out += CBC_BLOCK_SIZE_2;
                blocks -= 2;
            }

            auto *rk128 = (__m128i *) roundKeys;
            while (blocks > 0) {

                //
                // Remaining single blocks.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);

                __m128i tmp = _mm_xor_si128(data, rk128[48]);
                tmp = _mm_aesdec_si128(tmp, rk128[44]);
                tmp = _mm_aesdec_si128(tmp, rk128[40]);
                tmp = _mm_aesdec_si128(tmp, rk128[36]);
                tmp = _mm_aesdec_si128(tmp, rk128[32]);
                tmp = _mm_aesdec_si128(tmp, rk128[28]);
                tmp = _mm_aesdec_si128(tmp, rk128[24]);
                tmp = _mm_aesdec_si128(tmp, rk128[20]);
                tmp = _mm_aesdec_si128(tmp, rk128[16]);
                tmp = _mm_aesdec_si128(tmp, rk128[12]);
                tmp = _mm_aesdec_si128(tmp, rk128[8]);
                tmp = _mm_aesdec_si128(tmp, rk128[4]);
                tmp = _mm_aesdeclast_si128(tmp, rk128[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            return (size_t) (out - outStart);
        }


        //
        // AES CBC 256 Decryption
        //
        AesCBC256VaesFDec::AesCBC256VaesFDec() : CBC512wide() {

        }

        AesCBC256VaesFDec::~AesCBC256VaesFDec() = default;


        size_t AesCBC256VaesFDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;
            while (blocks >= 4) {
                __m512i data = _mm512_loadu_si512((__m512i *) in);

                __m512i tmp = _mm512_xor_si512(data, roundKeys[14]);

                tmp = _mm512_aesdec_epi128(tmp, roundKeys[13]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[12]);

                tmp = _mm512_aesdec_epi128(tmp, roundKeys[11]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[10]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm512_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm512_aesdeclast_epi128(tmp, roundKeys[0]);

                _mm512_storeu_si512((__m512i *) out, _mm512_xor_si512(
                        tmp,
                        _mm512_permutex2var_epi64(
                                data,
                                feedbackCtrl,
                                _mm512_castsi128_si512( feedback))));

                feedback = ((__m128i *) &data)[3];
                in += CBC_BLOCK_SIZE_4;
                out += CBC_BLOCK_SIZE_4;
                blocks -= 4;
            }


            auto rk256 = (__m256i *) roundKeys;
            while (blocks >= 2) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, rk256[28]);

                tmp = _mm256_aesdec_epi128(tmp, rk256[26]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[24]);

                tmp = _mm256_aesdec_epi128(tmp, rk256[22]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[20]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[18]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[16]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[14]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[12]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[10]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[8]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[6]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[4]);
                tmp = _mm256_aesdec_epi128(tmp, rk256[2]);
                tmp = _mm256_aesdeclast_epi128(tmp, rk256[0]);

                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));


                //fb[0] = ((__m128i *) &data)[1];
                feedback = _mm256_extracti128_si256(data, 1);
                in += CBC_BLOCK_SIZE_2;
                out += CBC_BLOCK_SIZE_2;
                blocks -= 2;
            }

            auto *rk128 = (__m128i *) roundKeys;
            while (blocks > 0) {

                //
                // Remaining single blocks.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);

                __m128i tmp = _mm_xor_si128(data, rk128[56]);
                tmp = _mm_aesdec_si128(tmp, rk128[52]);
                tmp = _mm_aesdec_si128(tmp, rk128[48]);
                tmp = _mm_aesdec_si128(tmp, rk128[44]);
                tmp = _mm_aesdec_si128(tmp, rk128[40]);
                tmp = _mm_aesdec_si128(tmp, rk128[36]);
                tmp = _mm_aesdec_si128(tmp, rk128[32]);
                tmp = _mm_aesdec_si128(tmp, rk128[28]);
                tmp = _mm_aesdec_si128(tmp, rk128[24]);
                tmp = _mm_aesdec_si128(tmp, rk128[20]);
                tmp = _mm_aesdec_si128(tmp, rk128[16]);
                tmp = _mm_aesdec_si128(tmp, rk128[12]);
                tmp = _mm_aesdec_si128(tmp, rk128[8]);
                tmp = _mm_aesdec_si128(tmp, rk128[4]);
                tmp = _mm_aesdeclast_si128(tmp, rk128[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            return (size_t) (out - outStart);
        }


    }
}


