//
//

#ifndef BC_LTS_C_UTIL_H
#define BC_LTS_C_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>


void memzero(void *const pnt, const size_t len);

# if defined(__GNUC__) || defined(__clang__)
#  define bc_likely(x)   __builtin_expect(!!(x), 1)
#  define bc_unlikely(x) __builtin_expect(!!(x), 0)
# else
#  define bc_likely(x)   (x)
#  define bc_unlikely(x) (x)
# endif

static inline void bc_assert_fail(const char *expr, const char *file, int line) {
    fprintf(stderr, "Assertion failed: %s at %s:%d\n", expr, file, line);
    fflush(stderr);
    abort();
}

#define bc_assert(x)                                        \
    do {                                                    \
        if (bc_unlikely(!(x))) {                            \
            bc_assert_fail(#x, __FILE__, __LINE__);         \
        }                                                   \
    } while (0)


#endif //BC_LTS_C_UTIL_H
