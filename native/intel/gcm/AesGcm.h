//
// Created  on 18/5/2022.
//

#ifndef CORENATIVE_AESGCM_H
#define CORENATIVE_AESGCM_H

#ifdef __linux__
#include <stdint.h>
#else

#include <cstdint>

#endif

#include <wmmintrin.h>
#include <vector>
#include "gcm.h"


namespace intel {
    namespace gcm {

#define BLOCK_SIZE 16
#define FOUR_BLOCKS 64

        void gfmul(__m128i a, __m128i b, __m128i *res);


        /**
         * This wrapper exists to deal with an issue with GCC where it will
         * warn:
         * warning: ignoring attributes on template argument ‘__m128i’ {aka ‘__vector(2) long long int’}
         * Rather than squash the warning it is better to deal with it and in this case it is only
         * used during the doFinal of GCM and only if addition associated text is supplied after init.
         *
         * Some conjecture indicates that the Intel C++ compiler does not have this issue.
         */
        struct _m128i_wrapper {
            __m128i val;
        };

        class Exponentiator {
        private:
            std::vector<_m128i_wrapper> *lookupPow2;

        public:
            Exponentiator();

            ~Exponentiator();

            void init(__m128i x);

            void exponentiateX(uint64_t pow, __m128i *output);

            void ensureAvailable(uint64_t bit);

        };


        class AesGcm : public GCM {
        public:
        private:

            static __m128i BSWAP_EPI64;
            static __m128i BSWAP_MASK;

            __m128i *roundKeys;

            // mac block
            unsigned char *macBlock;
            size_t macBlockLen;

            unsigned char *initAD = nullptr;
            size_t initADLen = 0;

            int atBlockPos = 0;
            size_t atLengthPre = 0;
            int64_t blocksRemaining = 0;

            __m128i X, H, Y, T, S_at, S_atPre, last_aad_block;


            bool encryption;
            uint32_t rounds;

            __m128i ctr1;

            // AD


            // bufBlock -- used for bytewise accumulation
            unsigned char *bufBlock;
            size_t bufBlockLen = 0;
            size_t bufBlockPtr = 0;
            __m128i last_block;

            size_t totalBytes = 0;
            size_t atLength = 0;

            __m128i initialX;
            __m128i initialY;
            __m128i initialT;
            __m128i initialH;

            Exponentiator *exp;

            void processBuffer(unsigned char *in, size_t inlen, unsigned char *out, size_t outputLen, size_t &read,
                               size_t &written);

            void processBlock(unsigned char *in, unsigned char *out, size_t outputLen);

            void processFourBlocks(unsigned char *in, unsigned char *out);

            void initCipher();

        public:
            AesGcm();

            ~AesGcm() override;

            void reset(bool keepMac) override;

            void init(bool encryption, unsigned char *key, size_t keyLen, unsigned char *nonce, size_t nonceLen,
                      unsigned char *initialText,
                      size_t initialTextLen, size_t macSizeBytes) override;


            void processAADBytes(unsigned char *in, size_t inOff, size_t len) override;

            size_t getMacLen() override;

            void getMac(unsigned char *dest) override;

            size_t getOutputSize(size_t len) override;

            size_t getUpdateOutputSize(size_t len) override;

            void processAADByte(unsigned char in) override;

            size_t processByte(unsigned char in, unsigned char *out, size_t outputLen) override;

            size_t
            processBytes(unsigned char *in, size_t inOff, size_t len, unsigned char *out, int outOff,
                         size_t outputLen) override;

            size_t doFinal(unsigned char *output, size_t outOff, size_t outLen) override;

            void setBlocksRemainingDown(int64_t down) override;

        };


    }
}

#endif //CORENATIVE_AESGCM_H
