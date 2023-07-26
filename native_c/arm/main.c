//
//

#include <printf.h>
#include <libc.h>


#include "debug_neon.h"


#include "ctr/ctr.h"



int main() {
    uint8_t key[16];
    uint8_t iv[15];

    memset(key, 0, 16);
    memset(iv, 0, 15);

    ctr_ctx *ctx = ctr_create_ctx();
    ctr_init(ctx, key, 16, iv, 15);

    size_t len = 65;

    uint8_t msg[len];
    memset(msg, 1, len);

    uint8_t res[len];
    memset(res, 2, len);

    size_t written = 0;

    ctr_process_bytes(ctx, msg, len, res, &written);
    print_bytes(res, len);


}