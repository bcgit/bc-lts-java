/*
 * Per-service CPU feature requirements for the ARM neon-le variant: the single
 * source of truth for which native services the host CPU can actually run.
 *
 * Each required mask lists every instruction-set feature the service's kernels
 * MAY EXECUTE as compiled in this variant (see the -march flags in
 * native_c/CMakeLists.txt). A service whose mask is not fully present in the host
 * HWCAPs is reported unavailable by the feature bridge (arm/jni/native_features.c);
 * the Java layer (DefaultNativeServices) then serves that algorithm with the
 * pure-Java implementation instead — a knocked-out service, never a SIGILL.
 *
 * When a kernel gains an instruction-set dependency: add the feature bit here and
 * to probe_system, and give the kernel's translation unit the matching per-file
 * -march in CMakeLists.txt. Never raise the variant-wide -march floor.
 */
#ifndef BC_LTS_C_ARM_SERVICES_H
#define BC_LTS_C_ARM_SERVICES_H

#include <stdint.h>
#include "../../jniutil/variant_selector.h"

#define BC_FEAT_NEON   (1u << 0)
#define BC_FEAT_AES    (1u << 1)   /* FEAT_AES: AESE/AESD/AESMC/AESIMC        */
#define BC_FEAT_PMULL  (1u << 2)   /* FEAT_PMULL: poly64 PMULL/PMULL2 (GHASH) */
#define BC_FEAT_SHA256 (1u << 3)   /* FEAT_SHA256: SHA256H/SHA256SU...        */
#define BC_FEAT_SHA512 (1u << 4)   /* FEAT_SHA512: SHA512H/SHA512SU...        */
#define BC_FEAT_SHA3   (1u << 5)   /* FEAT_SHA3: EOR3/RAX1/XAR/BCAX           */

typedef enum {
    BC_SVC_ECB = 0,
    BC_SVC_CBC,
    BC_SVC_CFB,
    BC_SVC_CTR,
    BC_SVC_CCM,
    BC_SVC_GCM,
    BC_SVC_SHA224,
    BC_SVC_SHA256,
    BC_SVC_SHA384,
    BC_SVC_SHA512,
    BC_SVC_SHA3,
    BC_SVC_SHAKE,
    BC_SVC_COUNT
} bc_arm_service;

static inline uint32_t bc_arm_host_feature_mask(const struct cpuid_info *info) {
    uint32_t mask = 0;
    if (info->neon) {
        mask |= BC_FEAT_NEON;
    }
    if (info->aes) {
        mask |= BC_FEAT_AES;
    }
    if (info->pmull) {
        mask |= BC_FEAT_PMULL;
    }
    if (info->sha256) {
        mask |= BC_FEAT_SHA256;
    }
    if (info->sha512) {
        mask |= BC_FEAT_SHA512;
    }
    if (info->sha3) {
        mask |= BC_FEAT_SHA3;
    }
    return mask;
}

static inline int bc_arm_service_available(const struct cpuid_info *info, bc_arm_service svc) {
    static const uint32_t required[BC_SVC_COUNT] = {
            [BC_SVC_ECB]    = BC_FEAT_NEON | BC_FEAT_AES,
            [BC_SVC_CBC]    = BC_FEAT_NEON | BC_FEAT_AES,
            [BC_SVC_CFB]    = BC_FEAT_NEON | BC_FEAT_AES,
            [BC_SVC_CTR]    = BC_FEAT_NEON | BC_FEAT_AES,
            /* CCM is CBC-MAC + CTR: AES only, no GHASH. */
            [BC_SVC_CCM]    = BC_FEAT_NEON | BC_FEAT_AES,
            /* GHASH multiplies in GF(2^128) via PMULL/PMULL2 (gcm/gcm_hash.h,
               mul/cmul128.c): FEAT_PMULL is a separate HWCAP from FEAT_AES, so a
               core with AES but not PMULL must not be handed native GCM. */
            [BC_SVC_GCM]    = BC_FEAT_NEON | BC_FEAT_AES | BC_FEAT_PMULL,
            [BC_SVC_SHA224] = BC_FEAT_NEON | BC_FEAT_SHA256,
            [BC_SVC_SHA256] = BC_FEAT_NEON | BC_FEAT_SHA256,
            [BC_SVC_SHA384] = BC_FEAT_NEON | BC_FEAT_SHA512,
            [BC_SVC_SHA512] = BC_FEAT_NEON | BC_FEAT_SHA512,
            [BC_SVC_SHA3]   = BC_FEAT_NEON | BC_FEAT_SHA3,
            [BC_SVC_SHAKE]  = BC_FEAT_NEON | BC_FEAT_SHA3,
    };

    if ((unsigned int) svc >= (unsigned int) BC_SVC_COUNT) {
        return 0;
    }

    const uint32_t need = required[svc];
    return (bc_arm_host_feature_mask(info) & need) == need;
}

#endif //BC_LTS_C_ARM_SERVICES_H
