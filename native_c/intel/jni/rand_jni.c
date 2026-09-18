//
//


#include "org_bouncycastle_crypto_NativeEntropySource.h"
#include "stdint.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/exceptions.h"
#include "../util/util.h"
#include "cpuid_util.h"
#include <immintrin.h>
#include <string.h>


#define RAND_MOD 8

//
// The retry budget for the hardware entropy sources comes from the java layer.
// See NativeServices.getMaxRNGRetries() and the property
// org.bouncycastle.native.rand.max_retries. A max_retries of 0 means retry
// without limit.
//
// Intel's "Digital Random Number Generator" software guide recommends a
// baseline of 10 retries for RDRAND and 100 for RDSEED. The java default of
// 1000 covers the slower RDSEED case with a wide margin. The margin is over
// the recommendation rather than over any measured failure: RDSEED declines
// routinely, and the cost of a retry is a pause instruction.
//
// An unbounded retry spins forever on a genuine hardware failure, which is what
// the bounded default prevents.
//

//
// Cached CPU support for the two hardware entropy instructions.
//
// seedBuffer takes useSeed from its caller, so the java-side service selection is
// not by itself a guarantee that the selected instruction exists on this CPU.
// Issuing RDRAND or RDSEED without support raises #UD, which kills the JVM
// instead of throwing. Re-check here, from a one-time cpuid read.
//
// The bits are the ones NativeFeatures probes: leaf 1 ecx bit 30 for RDRAND,
// leaf 7 ebx bit 18 for RDSEED. Any racing first call computes the same value and
// stores it, so the relaxed atomic accesses keep the fast path free without
// introducing a data race.
//
// The cpuid read is bounded, and the bound is why this matters. See cpuid_util.h.
//
#define RAND_SUPPORT_UNKNOWN 0
#define RAND_SUPPORT_YES     1
#define RAND_SUPPORT_NO      2

static int rdrandSupport = RAND_SUPPORT_UNKNOWN;
static int rdseedSupport = RAND_SUPPORT_UNKNOWN;

static int hardwareSupports(int useSeed) {
    int *slot = useSeed ? &rdseedSupport : &rdrandSupport;
    int cached = __atomic_load_n(slot, __ATOMIC_RELAXED);

    if (cached == RAND_SUPPORT_UNKNOWN) {
        cpuid_t info;
        int present;

        if (useSeed) {
            present = cpuid(&info, 7, 0) && (info.ebx & (1 << 18)) != 0;
        } else {
            present = cpuid(&info, 1, 0) && (info.ecx & (1 << 30)) != 0;
        }

        cached = present ? RAND_SUPPORT_YES : RAND_SUPPORT_NO;
        __atomic_store_n(slot, cached, __ATOMIC_RELAXED);
    }

    return cached == RAND_SUPPORT_YES;
}

//
// Fill one 64-bit word from the hardware RNG: one initial attempt, then up to
// max_retries more. Returns 1 on success, 0 if the source did not produce a
// value inside the budget.
//
static int rand_step_64(unsigned long long *val, int use_seed, int32_t max_retries) {
    // The caller rejects a negative max_retries before this point, so the cast
    // cannot turn into a huge budget.
    const uint64_t budget = (uint64_t) max_retries;
    uint64_t retries = 0;

    for (;;) {
        int flag = use_seed ? _rdseed64_step(val) : _rdrand64_step(val);
        if (flag != 0) {
            return 1;
        }

        // max_retries of 0 means retry without limit.
        if (max_retries != 0 && ++retries > budget) {
            return 0;
        }

        _mm_pause();
    }
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    isPredictionResistant
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_isPredictionResistant
        (JNIEnv *env, jobject jo) {
    return JNI_TRUE;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    modulus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_modulus
        (JNIEnv *env, jobject jo) {
    return RAND_MOD;
}

/*
 * Class:     org_bouncycastle_crypto_NativeEntropySource
 * Method:    seedBuffer
 * Signature: ([BZI)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_seedBuffer
        (JNIEnv *env, jobject jo, jbyteArray buf_, jboolean useSeed, jint maxRetries) {

    java_bytearray_ctx buf;
    const int use_seed = (useSeed == JNI_TRUE);

    init_bytearray_ctx(&buf);

    if (!load_bytearray_ctx(&buf, env, buf_)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid array");
        return;
    }

    if (buf.bytearray == NULL) {
        throw_java_NPE(env, "array cannot be null");
        goto exit;
    }

    if (buf.size % RAND_MOD != 0) {
        throw_java_illegal_argument(env, "array must be multiple of modulus");
        goto exit;
    }

    //
    // The sign check sits before the cast to uint64_t in rand_step_64: a negative
    // jint cast to an unsigned type becomes huge-but-positive, and Integer.MIN_VALUE
    // would turn into a budget of about 1.8e19 rather than a rejection.
    //
    // It also sits before the hardwareSupports gate and before the memzero, so a
    // rejected call reports the same on every CPU and leaves the caller's buffer
    // untouched.
    //
    if (maxRetries < 0) {
        throw_java_illegal_argument(env, "maxRetries cannot be negative");
        goto exit;
    }

    //
    // Re-check the instruction this call is about to issue. Reject before the
    // caller's buffer is touched, so a rejected call leaves it unchanged.
    //
    if (!hardwareSupports(use_seed)) {
        throw_java_invalid_state(env, use_seed
                ? "RDSEED is not supported by this CPU"
                : "RDRAND is not supported by this CPU");
        goto exit;
    }

    // Clear on the way in. Use memzero (un-elidable) rather than memset.
    memzero(buf.bytearray, buf.size);

    size_t count = buf.size / RAND_MOD;

    unsigned long long val = 0;

    for (size_t i = 0; i < count; i++) {
        if (!rand_step_64(&val, use_seed, maxRetries)) {
            // The hardware RNG exhausted its budget. Drop any partial entropy
            // already written so the caller does not observe a partly-filled
            // buffer alongside the exception. Use memzero (un-elidable) rather
            // than memset.
            memzero(buf.bytearray, buf.size);
            val = 0;
            throw_java_invalid_state(env, use_seed
                    ? "RDSEED persistently failed to produce entropy"
                    : "RDRAND persistently failed to produce entropy");
            goto exit;
        }
        memcpy(buf.bytearray + i * sizeof(val), &val, sizeof(val));
    }

    val = 0;

    exit:
    release_bytearray_ctx(&buf);

}
