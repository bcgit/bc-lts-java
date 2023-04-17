//
//

#include "bytearrays.h"
#include <stdint.h>

void init_bytearray_ctx(java_bytearray_ctx *ctx) {
    ctx->bytearray = NULL;
    ctx->array = NULL;
    ctx->size = 0;
    ctx->env = NULL;
}

int load_bytearray_ctx(java_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array) {
    ctx->env = env;
    ctx->array = array;
    ctx->size = 0;
    ctx->bytearray = NULL;

    if (array != NULL) {
        ctx->size = (size_t) (*env)->GetArrayLength(env, array);
        ctx->bytearray = (uint8_t *) (*env)->GetByteArrayElements(env, array, NULL);
        if (ctx->bytearray == NULL) {
            return 0;
        }
    }
    return 1;
}


/**
 * release_bytearray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_bytearray_ctx(java_bytearray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->bytearray == NULL || ctx->env == NULL) {
        return;
    }

    // ctx->array and ctx->env can't be NULL.
    (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, 0);
    ctx->bytearray = NULL;

}

