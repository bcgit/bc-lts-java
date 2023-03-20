//
// Created on 12/7/22.
//

#ifndef BCN_AESECBW256_H
#define BCN_AESECBW256_H

#include <cstdint>
#include <immintrin.h>
#include <jni_md.h>
#include "AesEcb.h"

/**
        * AES ECB with the original AES-NI instructions no AVX.
        */
namespace intel {
    namespace ecb {

        class AesEcb512W : public ECB {

        protected:
            __m128i *roundKeys;

        private:
            AesEcb512W &operator=(AesEcb512W const &);


        public:
            AesEcb512W(const AesEcb512W &i) = delete;

            AesEcb512W();

            ~AesEcb512W() override;

            uint32_t getMultiBlockSize() override;

            void reset() override;

            virtual void init(unsigned char *key) override =0;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override = 0;
        };


        class AesEcb512W128E : public AesEcb512W {

        public:
            AesEcb512W128E();

            ~AesEcb512W128E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks_,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb512W128D : public AesEcb512W {
        public:
            AesEcb512W128D();

            ~AesEcb512W128D() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb512W192E : public AesEcb512W {
        public:
            AesEcb512W192E();

            ~AesEcb512W192E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb512W192D : public AesEcb512W {

        public:
            AesEcb512W192D();

            ~AesEcb512W192D() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };


        class AesEcb512W256E : public AesEcb512W {
        public:
            AesEcb512W256E();

            ~AesEcb512W256E() override;

            void init(unsigned char *key) override;

            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb512W256D : public AesEcb512W {

        public:
            AesEcb512W256D();

            ~AesEcb512W256D() override;

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
