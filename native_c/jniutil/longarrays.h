//

#ifndef BC_LTS_longarrayS_H
#define BC_LTS_longarrayS_H

#include <stdbool.h>
#include <malloc.h>
#include <memory.h>
#include "jni.h"
#include <stdint.h>

typedef struct {
    int64_t *longarray;
    size_t size;
    JNIEnv *env;
    jlongArray array;
} java_longarray_ctx;


/**
 * Init a byte array context setting values to null.
 * It is safe to call release_longarray_ctx after applying this function.
 * @param ctx
 */
void init_longarray_ctx(java_longarray_ctx *ctx);

/**
 * Load a java byte array and claim it from the jvm
 * @param env
 * @param array
 * @return
 */
int load_longarray_ctx(java_longarray_ctx *ctx, JNIEnv *env, jlongArray array);


/**
 * release_longarray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_longarray_ctx(java_longarray_ctx *ctx);

#endif //BC_LTS_longarrayS_H
