//
//

#ifndef BC_LTS_C_VARIANT_SELECTOR_H
#define BC_LTS_C_VARIANT_SELECTOR_H

#include <stdbool.h>

struct cpuid_info {
    bool loaded;
    bool aes;
    bool sha256;
    bool sha512;
    bool sha3;
    bool neon;
    bool arm64;
    bool sve2;
};

void probe_system();

#endif //BC_LTS_C_VARIANT_SELECTOR_H
