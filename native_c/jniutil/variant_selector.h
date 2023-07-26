//
//

#ifndef BC_LTS_C_VARIANT_SELECTOR_H
#define BC_LTS_C_VARIANT_SELECTOR_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

struct cpuid_info {
    bool loaded;
    bool aes;
    bool sha256;
    bool sha512;
    bool sha3;
    bool neon;
    bool arm64;
    bool sve2;
    bool le;
};

bool is_le() {
    uint16_t w = 0xFF01;
    uint8_t *d = (uint8_t *) &w;
    return d[0] == 0x01;
}

void probe_system();

#endif //BC_LTS_C_VARIANT_SELECTOR_H
