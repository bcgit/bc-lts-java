

#include "org_bouncycastle_math_raw_Mul.h"
#include "../../jniutil/longarraycritical.h"
#include "../../jniutil/exceptions.h"
#include "../mul/cmul.h"
#include "../../jniutil/jni_asserts.h"

/*
 * Class:     org_bouncycastle_math_raw_Cmul
 * Method:    cmulAcc
 * Signature: ([JI[JI[J)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_math_raw_Mul_cmulAcc
        (JNIEnv *env, jclass cl, jlongArray xArr, jint x_off, jlongArray yArr, jint y_off, jlongArray zArr) {

    critical_longarray_ctx x;
    critical_longarray_ctx y;
    critical_longarray_ctx z;


    init_critical_long_ctx(&x, env, xArr);
    init_critical_long_ctx(&y, env, yArr);
    init_critical_long_ctx(&z, env, zArr);


    if (!load_critical_long_ctx(&x)) {
        throw_java_invalid_state(env, "jvm did not return valid x array");
        goto exit;
    }

    if (!load_critical_long_ctx(&y)) {
        release_critical_long_ctx(&x);
        throw_java_invalid_state(env, "jvm did not return valid y array");
        goto exit;
    }

    if (!load_critical_long_ctx(&z)) {
        release_critical_long_ctx(&x);
        release_critical_long_ctx(&y);
        throw_java_invalid_state(env, "jvm did not return valid z array");
        goto exit;
    }

    if (!critical_long_not_null(&x, "x array is null", env)) {
        goto exit;
    }

    if (!critical_long_not_null(&y, "y array is null", env)) {
        goto exit;
    }

    if (!critical_long_not_null(&z, "z array is null", env)) {
        goto exit;
    }


    if (x_off < 0) {
        throw_java_illegal_argument(env,
                                    "x offset is negative");
        goto exit;
    }


    if (x_off > x.size) {
        throw_java_illegal_argument(env, "x offset is past end of array");
        goto exit;
    }


    if (y_off < 0) {
        throw_java_illegal_argument(env,
                                    "y offset is negative");
        goto exit;
    }


    if (y_off > y.size) {
        throw_java_illegal_argument(env, "y offset is past end of array");
        goto exit;
    }

    // sign of offsets asserted by this point

    size_t x_size = x.size - (size_t) x_off;
    size_t y_size = y.size - (size_t) y_off;

    if (x_size != y_size) {
        throw_java_invalid_state(env, "x,y are not the same size");
        goto exit;
    }

    if (z.size < x_size * 2) {
        throw_java_invalid_state(env, "z is less than twice the size of x");
        goto exit;
    }

    // offset sign and position within array asserted by this point.
    int64_t *x_start = x.critical + (size_t) x_off;
    int64_t *y_start = y.critical + (size_t) y_off;


    cmul_acc(x_start, y_start, z.critical, x_size);


    exit:
    release_critical_long_ctx(&x);
    release_critical_long_ctx(&y);
    release_critical_long_ctx(&z);

}