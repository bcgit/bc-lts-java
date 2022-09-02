//
// Created on 18/5/2022.
//

#ifndef CORENATIVE_AESECB_H
#define CORENATIVE_AESECB_H


#include <cstdint>
#include <wmmintrin.h>
#include <jni_md.h>
#include "ecb.h"

namespace intel {

    namespace ecb {

        /**
         * AES ECB with the original AES-NI instructions no AVX.
         */
        class AesEcb : public ECB {
        private:

        public:
            AesEcb();

            ~AesEcb() override;

            uint32_t getMultiBlockSize() override;

            void init(bool encryption, unsigned char *key, unsigned long key_len) override;

            void reset() override;

            virtual size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override = 0;
        };


        class AesEcb128E : public AesEcb {
        public:
            AesEcb128E();

            ~AesEcb128E() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };
        class AesEcb128D : public AesEcb {
        public:
            AesEcb128D();

            ~AesEcb128D() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

        class AesEcb192E : public AesEcb {
        public:
            AesEcb192E();

            ~AesEcb192E() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };
        class AesEcb192D : public AesEcb {

        public:
            AesEcb192D();

            ~AesEcb192D() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };


        class AesEcb256E : public AesEcb {
        public:
            AesEcb256E();

            ~AesEcb256E() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };
        class AesEcb256D : public AesEcb {

        public:
            AesEcb256D();

            ~AesEcb256D() override;


            size_t processBlocks(
                    unsigned char *input,
                    size_t in_start,
                    size_t in_len,
                    uint32_t blocks,
                    unsigned char *output,
                    size_t out_start) override;
        };

    };


}


#endif //CORENATIVE_AESECB_H
