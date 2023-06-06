//
//

#include "longarrays.h"
#include <stdint.h>

void init_longarray_ctx(java_longarray_ctx *ctx) {
    ctx->longarray = NULL;
    ctx->array = NULL;
    ctx->size = 0;
    ctx->env = NULL;
}

int load_longarray_ctx(java_longarray_ctx *ctx, JNIEnv *env, jlongArray array) {
    ctx->env = env;
    ctx->array = array;
    ctx->size = 0;
    ctx->longarray = NULL;

    if (array != NULL) {
        ctx->size = (size_t) (*env)->GetArrayLength(env, array);
        ctx->longarray = (int64_t *) (*env)->GetLongArrayElements(env, array, NULL);
        if (ctx->longarray == NULL) {
            return 0;
        }
    }
    return 1;
}


/**
 * release_longarray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_longarray_ctx(java_longarray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->longarray == NULL || ctx->env == NULL) {
        return;
    }

    // ctx->array and ctx->env can't be NULL.
    (*(ctx->env))->ReleaseLongArrayElements(ctx->env, ctx->array, (jlong *) ctx->longarray, 0);
    ctx->longarray = NULL;

}

