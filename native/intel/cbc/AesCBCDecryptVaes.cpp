//
// Created  on 7/6/2022.
//

#include <emmintrin.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <cstring>
#include <iostream>
#include <immintrin.h>
#include <avxintrin.h>
#include <avx2intrin.h>
#include "AesCBCDecryptVaes.h"


namespace intel {
    namespace cbc {


        //
        // AES CBC 128 Decryption
        //
        AesCBC128VaesDec::AesCBC128VaesDec() : CBC256wide() {

        }

        AesCBC128VaesDec::~AesCBC128VaesDec() = default;

        size_t AesCBC128VaesDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;

            if (blocks % 2) {

                //
                // Single block first if odd blocks are supplied.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);
                auto *rk = (__m128i *) roundKeys;
                __m128i tmp = _mm_xor_si128(data, rk[20]);
                tmp = _mm_aesdec_si128(tmp, rk[18]);
                tmp = _mm_aesdec_si128(tmp, rk[16]);
                tmp = _mm_aesdec_si128(tmp, rk[14]);
                tmp = _mm_aesdec_si128(tmp, rk[12]);
                tmp = _mm_aesdec_si128(tmp, rk[10]);
                tmp = _mm_aesdec_si128(tmp, rk[8]);
                tmp = _mm_aesdec_si128(tmp, rk[6]);
                tmp = _mm_aesdec_si128(tmp, rk[4]);
                tmp = _mm_aesdec_si128(tmp, rk[2]);
                tmp = _mm_aesdeclast_si128(tmp, rk[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            while (blocks > 0) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, roundKeys[10]);


                tmp = _mm256_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm256_aesdeclast_epi128(tmp, roundKeys[0]);



                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));


                //fb[0] = ((__m128i *) &data)[1];
                feedback = _mm256_extracti128_si256(data, 1);
                in += CBC_BLOCK_SIZE * 2;
                out += CBC_BLOCK_SIZE * 2;
                blocks -= 2;
            }


            return (size_t) (out - outStart);
        }


        //
        // AES CBC 192 Decryption
        //
        AesCBC192VaesDec::AesCBC192VaesDec() : CBC256wide() {

        }

        AesCBC192VaesDec::~AesCBC192VaesDec() = default;


        size_t AesCBC192VaesDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;

            if (blocks % 2) {

                //
                // Single block first if odd blocks are supplied.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);
                auto *rk = (__m128i *) roundKeys;
                __m128i tmp = _mm_xor_si128(data, rk[24]);
                tmp = _mm_aesdec_si128(tmp, rk[22]);
                tmp = _mm_aesdec_si128(tmp, rk[20]);
                tmp = _mm_aesdec_si128(tmp, rk[18]);
                tmp = _mm_aesdec_si128(tmp, rk[16]);
                tmp = _mm_aesdec_si128(tmp, rk[14]);
                tmp = _mm_aesdec_si128(tmp, rk[12]);
                tmp = _mm_aesdec_si128(tmp, rk[10]);
                tmp = _mm_aesdec_si128(tmp, rk[8]);
                tmp = _mm_aesdec_si128(tmp, rk[6]);
                tmp = _mm_aesdec_si128(tmp, rk[4]);
                tmp = _mm_aesdec_si128(tmp, rk[2]);
                tmp = _mm_aesdeclast_si128(tmp, rk[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            while (blocks > 0) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, roundKeys[12]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[11]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[10]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm256_aesdeclast_epi128(tmp, roundKeys[0]);

                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));
                feedback = _mm256_extracti128_si256(data, 1);
                in += CBC_BLOCK_SIZE * 2;
                out += CBC_BLOCK_SIZE * 2;
                blocks -= 2;
            }


            return (size_t) (out - outStart);
        }


        //
        // AES CBC 256 Decryption
        //
        AesCBC256VaesDec::AesCBC256VaesDec() : CBC256wide() {

        }

        AesCBC256VaesDec::~AesCBC256VaesDec() = default;


        size_t AesCBC256VaesDec::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            auto fb = (__m128i *) &feedback;

            if (blocks % 2) {

                //
                // Single block first if odd blocks are supplied.
                //

                __m128i data = _mm_loadu_si128((__m128i *) in);
                auto *rk = (__m128i *) roundKeys;
                __m128i tmp = _mm_xor_si128(data, rk[28]);
                tmp = _mm_aesdec_si128(tmp, rk[26]);
                tmp = _mm_aesdec_si128(tmp, rk[24]);
                tmp = _mm_aesdec_si128(tmp, rk[22]);
                tmp = _mm_aesdec_si128(tmp, rk[20]);
                tmp = _mm_aesdec_si128(tmp, rk[18]);
                tmp = _mm_aesdec_si128(tmp, rk[16]);
                tmp = _mm_aesdec_si128(tmp, rk[14]);
                tmp = _mm_aesdec_si128(tmp, rk[12]);
                tmp = _mm_aesdec_si128(tmp, rk[10]);
                tmp = _mm_aesdec_si128(tmp, rk[8]);
                tmp = _mm_aesdec_si128(tmp, rk[6]);
                tmp = _mm_aesdec_si128(tmp, rk[4]);
                tmp = _mm_aesdec_si128(tmp, rk[2]);
                tmp = _mm_aesdeclast_si128(tmp, rk[0]);

                //result = _mm_xor_si128(tmp, feedback);
                _mm_storeu_si128((__m128i *) out, _mm_xor_si128(tmp, fb[0]));
                fb[0] = data;
                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
                blocks--;
            }


            while (blocks > 0) {
                __m256i data = _mm256_loadu_si256((__m256i *) in);
                __m256i tmp = _mm256_xor_si256(data, roundKeys[14]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[13]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[12]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[11]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[10]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[9]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[8]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[7]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[6]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[5]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[4]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[3]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[2]);
                tmp = _mm256_aesdec_epi128(tmp, roundKeys[1]);
                tmp = _mm256_aesdeclast_epi128(tmp, roundKeys[0]);

                _mm256_storeu_si256((__m256i *) out,
                                    _mm256_xor_si256(
                                            tmp,
                                            _mm256_set_m128i(
                                                    _mm256_extracti128_si256(data, 0), feedback)
                                    ));
                feedback = _mm256_extracti128_si256(data, 1);

                in += CBC_BLOCK_SIZE * 2;
                out += CBC_BLOCK_SIZE * 2;
                blocks -= 2;
            }


            return (size_t) (out - outStart);
        }


    }
}


