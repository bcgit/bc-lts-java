//
// Created  on 7/6/2022.
//

#ifndef BCFIPS_0_0_AESCBC_H
#define BCFIPS_0_0_AESCBC_H



#include <jni_md.h>
#include "CBC128wide.h"


namespace intel {
    namespace cbc {


        class AesCBC128Enc : public CBC128wide {
        private:
        public:
            AesCBC128Enc();

            ~AesCBC128Enc() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

        class AesCBC128Dec : public CBC128wide {
        private:



        public:
            AesCBC128Dec();

            ~AesCBC128Dec() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;
        };


        class AesCBC192Enc : public CBC128wide {
        private:


        public:
            AesCBC192Enc();

            ~AesCBC192Enc() override;
            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

        class AesCBC192Dec : public CBC128wide {
        private:


        public:
            AesCBC192Dec();

            ~AesCBC192Dec() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;


        };

        class AesCBC256Enc : public CBC128wide {
        private:



        public:
            AesCBC256Enc();

            ~AesCBC256Enc() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

        class AesCBC256Dec : public CBC128wide {
        private:




        public:
            AesCBC256Dec();

            ~AesCBC256Dec() override;

            size_t processBlocks(unsigned char *in, uint32_t blocks, unsigned char *out) override;

        };

    }
}

#endif //BCFIPS_0_0_AESCBC_H
