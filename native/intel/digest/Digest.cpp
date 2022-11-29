

#include "Digest.h"

//
// Created  on 27/6/2022.
//

#include "Digest.h"
#include "SHA256.h"
#include <stdexcept>

namespace intel {
    namespace digest {

        Digest *makeDigest(int type) {

            switch (type) {
                case 1:
                    return new Sha256();
                default:
                    throw std::invalid_argument("unknown digest on make");
            }

        }

        void destroyDigest(int type, Digest *dig) {

            switch (type) {
                case 1:
                    delete ((Sha256 *) dig);
                    break;
                default:
                    throw std::invalid_argument("unknown digest type on destroy");
            }

        }


        Digest::~Digest() = default;


    }
}