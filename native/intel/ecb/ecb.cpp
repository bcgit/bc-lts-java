//
// Created on 22/7/2022.
//

#include "ecb.h"
#include "AesEcb.h"
#include <stdexcept>
#include <cstring>
#include <iostream>

namespace intel {
    namespace ecb {



        ECB::ECB() {
            roundKeys = new __m128i[15];
        }

        ECB::~ECB() {
            memset(roundKeys, 0, 15 * sizeof(__m128i));
            delete[] roundKeys;
        }




        AesEcb::AesEcb() : ECB() {

        }

        AesEcb::~AesEcb() = default;

//        void AesEcb::init(bool encryption, unsigned char *key, unsigned long key_len) {
//            reset();
//            memset(roundKeys, 0, 15 * sizeof(__m128i));
//            switch (key_len) {
//                case 16:
//                    //this->xform = encryption ? intel::aes::_aes_128_enc : intel::aes::_aes_128_dec;
//                    init_128(roundKeys, key, encryption);
//                    break;
//                case 24:
//                    //this->xform = encryption ? intel::aes::_aes_192_enc : intel::aes::_aes_192_dec;
//                    init_192(roundKeys, key, encryption);
//                    break;
//                case 32:
//                    // this->xform = encryption ? intel::aes::_aes_256_enc : intel::aes::_aes_256_dec;
//                    init_256(roundKeys, key, encryption);
//                    break;
//                default:
//                    throw std::invalid_argument("key size must be 16,24 or 32 bytes");
//            }
//
//        }

        void AesEcb::reset() {
            //memset(roundKeys, 0, sizeof(__m128i) * 15);
        }

    }
}
