//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_AesCBCDecryptVaesF_H
#define BCFIPS_0_0_AesCBCDecryptVaesF_H


#include <emmintrin.h>
#include <wmmintrin.h>
#include <jni_md.h>
#include "CBC512wide.h"


namespace intel {
    namespace cbc {

        class AesCBC128VaesFDec : public CBC512wide {
        private:

        public:
            AesCBC128VaesFDec();

            ~AesCBC128VaesFDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;
        };


        class AesCBC192VaesFDec : public CBC512wide {
        private:



        public:
            AesCBC192VaesFDec();

            ~AesCBC192VaesFDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;


        };


        class AesCBC256VaesFDec : public CBC512wide {
        private:

        public:
            AesCBC256VaesFDec();

            ~AesCBC256VaesFDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

    }
}

#endif //BCFIPS_0_0_AESCBC_H
