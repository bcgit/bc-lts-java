//

#ifndef BC_FIPS_BYTEARRAYS_H
#define BC_FIPS_BYTEARRAYS_H

#include <stdbool.h>
#include "jni.h"
#include <stdint.h>

typedef struct {
    uint8_t *bytearray;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
    jboolean is_copy;
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


/**
 * release_bytearray_ctx_unchanged releases a java byte ctx whose contents the native code did not
 * change (for example a read-only key, IV, or AAD array). It uses JNI_ABORT, so the native copy is
 * discarded without copy-back.
 * @param ctx
 */
void release_bytearray_ctx_unchanged(java_bytearray_ctx *ctx);


/**
 * release_bytearray_ctx_secret releases a java byte ctx holding a secret the native code did not
 * change, such as a key. Where the JVM handed out a copy, the copy is cleared before it is freed,
 * and nothing is copied back, so the caller's array is untouched.
 * @param ctx
 */
void release_bytearray_ctx_secret(java_bytearray_ctx *ctx);


/**
 * release_bytearray_ctx_secret_output releases a java byte ctx that the native code filled with a
 * secret, such as seed material. The contents are copied back to the java array, then any copy the
 * JVM handed out is cleared before it is freed.
 * @param ctx
 */
void release_bytearray_ctx_secret_output(java_bytearray_ctx *ctx);

#endif //BC_FIPS_BYTEARRAYS_H
