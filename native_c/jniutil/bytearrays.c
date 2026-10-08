//
//

#include "bytearrays.h"
#include <stdint.h>

/**
 * Clear a buffer through a volatile pointer, so the stores cannot be elided as dead.
 */
static void clear_secret(uint8_t *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len-- > 0) {
        *p++ = 0;
    }
}

void init_bytearray_ctx(java_bytearray_ctx *ctx) {
    ctx->bytearray = NULL;
    ctx->array = NULL;
    ctx->size = 0;
    ctx->env = NULL;
    ctx->is_copy = JNI_FALSE;
}

int load_bytearray_ctx(java_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array) {
    ctx->env = env;
    ctx->array = array;
    ctx->size = 0;
    ctx->bytearray = NULL;
    ctx->is_copy = JNI_FALSE;

    if (array != NULL) {
        ctx->size = (size_t) (*env)->GetArrayLength(env, array);
        ctx->bytearray = (uint8_t *) (*env)->GetByteArrayElements(env, array, &ctx->is_copy);
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


/**
 * release_bytearray_ctx_unchanged releases a java byte ctx whose contents the native code did NOT
 * change (for example a read-only key, IV, or AAD array). It uses JNI_ABORT, so the native copy is
 * freed WITHOUT copy-back.
 * @param ctx
 */
void release_bytearray_ctx_unchanged(java_bytearray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->bytearray == NULL || ctx->env == NULL) {
        return;
    }

    // ctx->array and ctx->env can't be NULL.
    (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, JNI_ABORT);
    ctx->bytearray = NULL;

}


/**
 * release_bytearray_ctx_secret releases a java byte ctx holding a secret the native code did not
 * change, such as a key. Where the JVM handed out a copy, the copy is cleared before it is freed.
 * JNI_ABORT means nothing is copied back, so the cleared copy never reaches the caller's array, and
 * where the JVM handed out the array itself it is left as it is.
 * @param ctx
 */
void release_bytearray_ctx_secret(java_bytearray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->bytearray == NULL || ctx->env == NULL) {
        return;
    }

    if (ctx->is_copy) {
        clear_secret(ctx->bytearray, ctx->size);
    }
    (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, JNI_ABORT);
    ctx->bytearray = NULL;
}


/**
 * release_bytearray_ctx_secret_output releases a java byte ctx that the native code filled with a
 * secret, such as seed material. JNI_COMMIT copies the contents back to the java array without
 * freeing the copy, which is then cleared and freed with JNI_ABORT.
 * @param ctx
 */
void release_bytearray_ctx_secret_output(java_bytearray_ctx *ctx) {
    if (ctx == NULL || ctx->array == NULL || ctx->bytearray == NULL || ctx->env == NULL) {
        return;
    }

    if (ctx->is_copy) {
        (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, JNI_COMMIT);
        clear_secret(ctx->bytearray, ctx->size);
        (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, JNI_ABORT);
    } else {
        (*(ctx->env))->ReleaseByteArrayElements(ctx->env, ctx->array, (jbyte *) ctx->bytearray, 0);
    }
    ctx->bytearray = NULL;
}
