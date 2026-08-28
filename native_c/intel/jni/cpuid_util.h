//
//

#ifndef BC_LTS_C_CPUID_H
#define BC_LTS_C_CPUID_H

typedef struct cpuid_struct {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} cpuid_t;

//
// Read a cpuid leaf, bounded by the range the CPU reports.
//
// Returns 1 and fills info when the leaf is in range. Returns 0 with info zeroed
// when it is not. A caller that only tests feature bits may ignore the return
// value: the zeroed registers make every bit test read as absent, so an absent
// leaf fails closed.
//
// The bound matters. CPUID with a leaf above the supported maximum does not
// return zeros. It returns the values of the highest supported leaf in that
// range. So an unbounded read of leaf 7, on a CPU whose maximum basic leaf is
// below 7, yields some other leaf's registers. A feature bit in that unrelated
// value can read as set. That reports a feature present on hardware which lacks
// it, and the caller then selects an instruction the CPU cannot execute.
//
// Leaf 0 eax carries the maximum basic leaf. Leaf 0x80000000 eax carries the
// maximum extended leaf. Read the one that matches the requested leaf first.
//
// Two ranges are known here, basic and extended. A leaf outside both, such as a
// hypervisor leaf in the 0x40000000 range, is bounded against the basic maximum
// and so reads as absent. No caller needs one today. A caller that does will need
// its own range check, because this helper will refuse it.
//
// This helper is static inline in a header on purpose. The probe library and the
// variant libraries are separate shared objects, so one non-static definition
// could not serve both. This gives one definition in source, a private copy for
// each translation unit, and no cross-unit linkage.
//
static inline int cpuid(cpuid_t *info, unsigned int leaf, unsigned int subleaf) {
    unsigned int base = (leaf >= 0x80000000u) ? 0x80000000u : 0u;
    cpuid_t probe;

    info->eax = 0;
    info->ebx = 0;
    info->ecx = 0;
    info->edx = 0;

    //
    // CPUID writes all four registers, so all four are declared as outputs. If
    // ecx were declared only as an input, the compiler would believe it still
    // held the value afterwards, and the next call would inherit a garbage
    // subleaf. Leaf 7 with a garbage subleaf returns zeros, which reads as
    // "feature absent" on hardware that has it.
    //
    __asm__ volatile("cpuid"
            : "=a" (probe.eax), "=b" (probe.ebx), "=c" (probe.ecx), "=d" (probe.edx)
            : "a" (base), "c" (0u)
            );

    //
    // A CPU with no extended leaves answers the 0x80000000 query with a basic
    // leaf number, which is below the base. Treat that as an empty range. Leaf 0
    // always exists where cpuid exists, so the basic range is never empty.
    //
    if (probe.eax < base || leaf > probe.eax) {
        return 0;
    }

    __asm__ volatile("cpuid"
            : "=a" (info->eax), "=b" (info->ebx), "=c" (info->ecx), "=d" (info->edx)
            : "a" (leaf), "c" (subleaf)
            );

    return 1;
}

#endif //BC_LTS_C_CPUID_H
