//
//


#include "org_bouncycastle_crypto_NativeEntropySource.h"
#include "stdint.h"
#include "../../jniutil/bytearrays.h"
#include "../../jniutil/exceptions.h"
#include "../util/util.h"
#include <immintrin.h>
#include <string.h>


#define RAND_MOD 8

//
// Bounded retry counts for the hardware entropy sources.
// Per Intel SDM and Intel's "Digital Random Number Generator" software guide.
// They have doubled for safety.
//
#define MAX_RDRAND_RETRIES 20   // Intel-recommended baseline: 10
#define MAX_RDSEED_RETRIES 200  // Intel-recommended baseline: 100

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
#define RAND_SUPPORT_UNKNOWN 0
#define RAND_SUPPORT_YES     1
#define RAND_SUPPORT_NO      2

static int rdrandSupport = RAND_SUPPORT_UNKNOWN;
static int rdseedSupport = RAND_SUPPORT_UNKNOWN;

typedef struct rand_cpuid_struct {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} rand_cpuid_t;

//
// Read a basic cpuid leaf, bounded. Returns 1 and fills info when the leaf is
// supported, 0 with info zeroed when it is not.
//
// The bound matters. CPUID with a leaf above the highest basic leaf does not
// return zeros: it returns the values of the highest supported leaf. So reading
// leaf 7 unbounded on a CPU whose maximum basic leaf is below 7 yields some other
// leaf's registers, and bit 18 of that unrelated ebx can read as set. That would
// report RDSEED present on exactly the old hardware this guard protects. Leaf 0
// eax carries the maximum basic leaf, so check it first.
//
// Only basic leaves are read here. An extended leaf, 0x80000000 and above, would
// need the same check against leaf 0x80000000's eax instead.
//
static int rand_cpuid(rand_cpuid_t *info, unsigned int leaf, unsigned int subleaf) {
    unsigned int maxBasicLeaf;
    rand_cpuid_t probe;

    info->eax = 0;
    info->ebx = 0;
    info->ecx = 0;
    info->edx = 0;

    //
    // CPUID writes all four registers, so all four are declared as outputs. If ecx
    // were declared only as an input the compiler would believe it still held 0
    // afterwards, and the next call would inherit a garbage subleaf.
    //
    __asm__ volatile("cpuid"
            : "=a" (probe.eax), "=b" (probe.ebx), "=c" (probe.ecx), "=d" (probe.edx)
            : "a" (0u), "c" (0u)
            );

    maxBasicLeaf = probe.eax;

    if (leaf > maxBasicLeaf) {
        return 0;
    }

    __asm__ volatile("cpuid"
            : "=a" (info->eax), "=b" (info->ebx), "=c" (info->ecx), "=d" (info->edx)
            : "a" (leaf), "c" (subleaf)
            );

    return 1;
}

static int hardwareSupports(int useSeed) {
    int *slot = useSeed ? &rdseedSupport : &rdrandSupport;
    int cached = __atomic_load_n(slot, __ATOMIC_RELAXED);

    if (cached == RAND_SUPPORT_UNKNOWN) {
        rand_cpuid_t info;
        int present;

        if (useSeed) {
            present = rand_cpuid(&info, 7, 0) && (info.ebx & (1 << 18)) != 0;
        } else {
            present = rand_cpuid(&info, 1, 0) && (info.ecx & (1 << 30)) != 0;
        }

        cached = present ? RAND_SUPPORT_YES : RAND_SUPPORT_NO;
        __atomic_store_n(slot, cached, __ATOMIC_RELAXED);
    }

    return cached == RAND_SUPPORT_YES;
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
 * Signature: ([BZ)V
 */
JNIEXPORT void JNICALL Java_org_bouncycastle_crypto_NativeEntropySource_seedBuffer
        (JNIEnv *env, jobject jo, jbyteArray buf_, jboolean useSeed) {

    java_bytearray_ctx buf;
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
    // Re-check the instruction this call is about to issue. Reject before the
    // caller's buffer is touched, so a rejected call leaves it unchanged.
    //
    if (!hardwareSupports(useSeed == JNI_TRUE)) {
        throw_java_invalid_state(env, useSeed == JNI_TRUE
                ? "RDSEED is not supported by this CPU"
                : "RDRAND is not supported by this CPU");
        goto exit;
    }

    // Clear on the way in. Use memzero (un-elidable) rather than memset.
    memzero(buf.bytearray, buf.size);

    size_t count = buf.size / RAND_MOD;

    unsigned long long val = 0;

    if (useSeed) {
        // Use RDSEED
        for (size_t i = 0; i < count; i++) {
            int flag = _rdseed64_step(&val);
            int tries = 0;
            while (flag == 0) {
                if (++tries > MAX_RDSEED_RETRIES) {
                    // Drop any partial entropy already written so the caller
                    // does not observe a partly-filled buffer alongside the
                    // exception. Use memzero (un-elidable) rather than memset.
                    memzero(buf.bytearray, buf.size);
                    throw_java_invalid_state(env,
                        "RDSEED persistently failed to produce entropy");
                    goto exit;
                }
                _mm_pause();
                flag = _rdseed64_step(&val);
            }
            memcpy(buf.bytearray + i * sizeof(val), &val, sizeof(val));
        }
    } else {
        // Use RDRAND
        for (size_t i = 0; i < count; i++) {
            int flag = _rdrand64_step(&val);
            int tries = 0;
            while (flag == 0) {
                if (++tries > MAX_RDRAND_RETRIES) {
                    memzero(buf.bytearray, buf.size);
                    throw_java_invalid_state(env,
                        "RDRAND persistently failed to produce entropy");
                    goto exit;
                }
                _mm_pause();
                flag = _rdrand64_step(&val);
            }
            memcpy(buf.bytearray + i * sizeof(val), &val, sizeof(val));
        }
    }


    exit:
    release_bytearray_ctx(&buf);

}
