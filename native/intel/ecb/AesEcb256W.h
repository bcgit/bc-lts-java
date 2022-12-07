//
// Created on 12/7/22.
//

#ifndef BCN_AESECBW256_H
#define BCN_AESECBW256_H

#include <cstdint>
#include <immintrin.h>
#include <jni_md.h>
#include "ecb.h"

/**
        * AES ECB with the original AES-NI instructions no AVX.
        */
namespace intel {
    namespace ecb {

        class AesEcb256W : public ECB {
        protected:
            __m256i *roundKeys256;

        public:
            AesEcb256W();

            ~AesEcb256W() override;

            uint32_t getMultiBlockSize() override;

            void reset() override;

            virtual void init(unsigned char *key) override = 0;

            virtual size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override = 0;
        };


        class AesEcb256W128E : public AesEcb256W {

        public:
            AesEcb256W128E();

            ~AesEcb256W128E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb256W128D : public AesEcb256W {
        public:
            AesEcb256W128D();

            ~AesEcb256W128D() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb256W192E : public AesEcb256W {
        public:
            AesEcb256W192E();

            ~AesEcb256W192E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };
        class AesEcb256W192D : public AesEcb256W {

        public:
            AesEcb256W192D();

            ~AesEcb256W192D() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };


        class AesEcb256W256E : public AesEcb256W {
        public:
            AesEcb256W256E();

            ~AesEcb256W256E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };
        class AesEcb256W256D : public AesEcb256W {

        public:
            AesEcb256W256D();

            ~AesEcb256W256D() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

    }
}


#endif //BCN_AESECBW256_H
