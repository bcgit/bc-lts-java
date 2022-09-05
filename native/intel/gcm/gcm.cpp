//
// Created on 26/7/2022.
//

#include "gcm.h"
#include "AesGcm.h"

namespace intel::gcm {
    GCM *GCM::makeGCM() {
        return new AesGcm();
    }

    GCM::GCM() {

    };

    GCM::~GCM() = default;

}
