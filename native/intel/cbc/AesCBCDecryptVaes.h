//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_AesCBCDecryptVaes_H
#define BCFIPS_0_0_AesCBCDecryptVaes_H


#include <emmintrin.h>
#include <wmmintrin.h>
#include <jni_md.h>
#include "CBC256wide.h"


namespace intel {
    namespace cbc {

        class AesCBC128VaesDec : public CBC256wide {
        private:

        public:
            AesCBC128VaesDec();

            ~AesCBC128VaesDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;
        };


        class AesCBC192VaesDec : public CBC256wide {
        private:



        public:
            AesCBC192VaesDec();

            ~AesCBC192VaesDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;


        };


        class AesCBC256VaesDec : public CBC256wide {
        private:

        public:
            AesCBC256VaesDec();

            ~AesCBC256VaesDec() override;

            size_t processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

    }
}

#endif //BCFIPS_0_0_AesCBCDecryptVaes_H
