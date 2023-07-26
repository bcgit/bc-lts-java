//

//

#include <stdbool.h>
#include "bytearraycritical.h"


void init_critical_ctx(critical_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array) {

    ctx->env = env;
    ctx->array = array;
    ctx->size = 0;
    ctx->critical = NULL;

    if (array != NULL) {
        ctx->size = (size_t) (*env)->GetArrayLength(env, array);
    }
}


/**
 * Get the critical array ptr if necessary from the jvm if not already claimed, and not a null byte array.
 * @param ctx pointer to the java_bytearray_ctx
 * @return true if, the underlying array is null, the array has already been claimed, or claiming was successful.
 * false if the jvm was expected to return a pointer but did not do so.
 */
bool load_critical_ctx(critical_bytearray_ctx *ctx) {
    if (ctx == NULL) {
        return false; // fail on no context
    }

    if (ctx->array == NULL || ctx->critical != NULL) {
        return true; // Already claimed from jvm or the java side passed a null array.
    }


    ctx->critical = (*(ctx->env))->GetPrimitiveArrayCritical(ctx->env, ctx->array, NULL);
    if (ctx->critical == NULL) {
        return false; // We didn't get a valid array.
    }

    return true;
}


/**
 * release_critical_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_critical_ctx(critical_bytearray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->critical == NULL || ctx->env == NULL) {
        return;
    }

//    printf("crit >> %p\n",ctx->critical);
//    fflush(stdout);

    // ctx->array and ctx->env can't be NULL.
    (*(ctx->env))->ReleasePrimitiveArrayCritical(ctx->env, ctx->array, (jbyte *) ctx->critical, 0);
    ctx->critical = NULL;
}