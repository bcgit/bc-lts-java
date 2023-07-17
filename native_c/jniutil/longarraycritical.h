//
//

#ifndef BC_FIPS_longarrayCRITICAL_H
#define BC_FIPS_longarrayCRITICAL_H


#include <stddef.h>
#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int64_t *critical;
    size_t size;
    JNIEnv *env;
    jlongArray array;
} critical_longarray_ctx;


void init_critical_long_ctx(critical_longarray_ctx *ctx, JNIEnv *env, jlongArray array);


/**
 * Actually claim the byte ctx from the jvm if not already claimed.
 * @param ctx pointer to the java_longarray_ctx
 * @return non zero on success
 */
bool load_critical_long_ctx(critical_longarray_ctx *ctx);


/**
 * release_longarray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_critical_long_ctx(critical_longarray_ctx *ctx);

#endif //BC_FIPS_longarrayCRITICAL_H
