//
// Created by 25/7/2022.
//

#include <stdexcept>
#include <cstring>
#include "CBC.h"
#include "AesCBC.h"

namespace intel {
    namespace cbc {


        CBC *CBC::makeCBC(int keysize, bool direction) {
            //
            // Variations derived from 3-50 Vol. 2A of INSTRUCTION SET REFERENCE, A-L
            // ~Page 154 " AESDEC—Perform One Round of an AES Decryption Flow"
            //
            // Limited to 16 byte block size versions.
            //
            return new AesCBC128Enc();

        }



        CBC::CBC() {
            roundKeys = new __m128i[15];
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
            encryption = false;
        }

        CBC::~CBC() {
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
            feedback = _mm_setzero_si128();
            initialFeedback = _mm_setzero_si128();
        }

        void CBC::init(
                bool encryption,
                unsigned char *key,
                unsigned long keylen,
                unsigned char *iv,
                unsigned long ivlen) {

            this->encryption = encryption;


            if (key == nullptr && keylen != 0) {
                throw std::invalid_argument("null key with non zero key length");
            }

            if (iv == nullptr || ivlen != CBC_BLOCK_SIZE) {
                throw std::invalid_argument("null iv or iv is not block size");
            }

            // We need to reset the iv on each call, but the key can be null so only the iv changes.
            feedback = _mm_loadu_si128((__m128i *) (iv));
            initialFeedback = feedback;

            // key was not null so set up transformation.
            if (key != nullptr) {
                memset(roundKeys, 0, 15 * sizeof(__m128i));
                init(key);


//                switch (keylen) {
//                    case 16:
//                        this->xform = encryption ? intel::aes::_aes_128_cbc_enc : intel::aes::_aes_128_cbc_dec;
//                        intel::aes::init_128(roundKeys, key, encryption);
//                        break;
//                    case 24:
//                        this->xform = encryption ? intel::aes::_aes_192_cbc_enc : intel::aes::_aes_192_cbc_dec;
//                        intel::aes::init_192(roundKeys, key, encryption);
//                        break;
//                    case 32:
//                        this->xform = encryption ? intel::aes::_aes_256_cbc_enc : intel::aes::_aes_256_cbc_dec;
//                        intel::aes::init_256(roundKeys, key, encryption);
//                        break;
//                    default:
//                        throw std::invalid_argument("key size must be 16,24 or 32 bytes");
            }


        }

        void CBC::reset() {
            feedback = initialFeedback;
        }

        uint32_t CBC::getMultiBlockSize() {
            return CBC_BLOCK_SIZE;
        }

        size_t CBC::processBlock(unsigned char *in, uint32_t blocks, unsigned char *out) {
            unsigned char *outStart = out;
            for (int t = 0; t < blocks; t++) {

                auto data = _mm_loadu_si128((__m128i *) in);
                auto result = _mm_setzero_si128();

                xform(data, roundKeys, result, feedback);

                _mm_storeu_si128((__m128i *) out, result);

                in += CBC_BLOCK_SIZE;
                out += CBC_BLOCK_SIZE;
            }

            return out - outStart;
        }

    }


    }


