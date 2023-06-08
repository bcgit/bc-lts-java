//

#ifndef BC_FIPS_BYTEARRAYS_H
#define BC_FIPS_BYTEARRAYS_H

#include <stdbool.h>
#include <stdlib.h>
#include <memory.h>
#include "jni.h"
#include <stdint.h>

typedef struct {
    uint8_t *bytearray;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
} java_bytearray_ctx;


/**
 * Init a byte array context setting values to null.
 * It is safe to call release_bytearray_ctx after applying this function.
 * @param ctx
 */
void init_bytearray_ctx(java_bytearray_ctx *ctx);

/**
 * Load a java byte array and claim it from the jvm
 * @param env
 * @param array
 * @return
 */
int load_bytearray_ctx(java_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);


/**
 * release_bytearray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_bytearray_ctx(java_bytearray_ctx *ctx);

#endif //BC_FIPS_BYTEARRAYS_H
