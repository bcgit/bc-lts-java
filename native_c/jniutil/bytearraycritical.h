//
//

#ifndef BC_FIPS_BYTEARRAYCRITICAL_H
#define BC_FIPS_BYTEARRAYCRITICAL_H


#include <stddef.h>
#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t *critical;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
} critical_bytearray_ctx;




void init_critical_ctx(critical_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);


/**
 * Actually claim the byte ctx from the jvm if not already claimed.
 * @param ctx pointer to the java_bytearray_ctx
 * @return non zero on success
 */
bool load_critical_ctx(critical_bytearray_ctx *ctx);


/**
 * release_bytearray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_critical_ctx(critical_bytearray_ctx *ctx);

#endif //BC_FIPS_BYTEARRAYCRITICAL_H
