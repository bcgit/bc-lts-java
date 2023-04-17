//
//

#ifndef BC_FIPS_JNI_ASSERTS_H
#define BC_FIPS_JNI_ASSERTS_H


#include "bytearraycritical.h"
#include "bytearrays.h"
#include "exceptions.h"


static inline bool check_range(size_t size, size_t offset, size_t len) {
    return (len <= size) && (offset <= size - len);
}

static inline bool critical_not_null(critical_bytearray_ctx *in, const char *failMsg, JNIEnv *env) {

    if (in == NULL || in->array == NULL) {
        throw_java_NPE(env, failMsg);
        return false;
    }

    return true;
}

static inline bool bytearray_not_null(java_bytearray_ctx *in, const char *failMsg, JNIEnv *env) {

    if (in == NULL || in->array == NULL) {
        throw_java_NPE(env, failMsg);
        return false;
    }

    return true;
}

/**
 * This is a collection of tests for input and output arrays along with their offsets and an overall length.,
 * @param in input critical array
 * @param input_offset  input offset
 * @param len total bytes to be processed
 * @param output the output array
 * @param output_offset the output offset
 * @param env the java env
 * @return true if successful, throws java exception and returns false if not successful.
 */

static inline bool input_and_output_critical_are_in_range_for_offsets_and_len(
        critical_bytearray_ctx *in,
        const int input_offset,
        const int len,
        critical_bytearray_ctx *output,
        int output_offset, JNIEnv *env) {

    if (input_offset < 0) {
        throw_bc_data_length_exception(env, "input offset was negative");
        return false;
    }

    if (output_offset < 0) {
        throw_bc_output_length_exception(env, "output offset was negative");
        return false;
    }

    if (len < 0) {
        throw_bc_data_length_exception(env, "len was negative");
        return false;
    }

    if (!check_range(in->size, (size_t) input_offset, (size_t) len)) {
        throw_bc_data_length_exception(env,
                                       "input buffer too short");
        return false;
    }

    if (!check_range(output->size, (size_t) output_offset, (size_t) len)) {
        throw_bc_output_length_exception(env,
                                         "output buffer too short");
        return false;
    }


    return true;

}


static inline bool process_critical_blocks_valid(
        critical_bytearray_ctx *in,
        const int in_offset,
        const int blockCount,
        critical_bytearray_ctx *out,
        int out_offset,
        JNIEnv *env,
        const int blockSize) {

    if (in_offset < 0) {
        throw_bc_data_length_exception(env,
                                       "input offset is negative");
        return false;
    }

    if (out_offset < 0) {

        throw_bc_output_length_exception(env,
                                         "output offset is negative");
        return false;
    }

    if (blockCount < 0) {
        throw_bc_data_length_exception(env,
                                       "blockCount is negative");
        return false;
    }

    size_t extent = (size_t) blockSize * (size_t) blockCount;


    if (!check_range(in->size, (size_t) in_offset, extent)) {
        throw_bc_data_length_exception(env,
                                       "input buffer too short");
        return false;
    }


    if (!check_range(out->size, (size_t) out_offset, extent)) {
        throw_bc_output_length_exception(env,
                                         "output buffer too short");
        return false;
    }


    return true;

}

/**
 * Check and iv is not null and 16 bytes long, throws java exceptions if not met.
 * @param env  the java environment.
 * @param iv the array containing the iv.
 * @return
 */
static inline bool ivlen_is_16_and_not_null(JNIEnv *env, java_bytearray_ctx *iv) {
    if (iv->array == NULL) {
        throw_java_NPE(env, "iv is null");
        return false;
    }
    if (iv->size == 16) {
        return true;
    }

    throw_java_illegal_argument(env, "iv must be only 16 bytes");

    return false;
}

/**
 * Assert aes key sizes, throws java exceptions if not.
 * @param env java env var
 * @param key the key
 * @return true if ok
 */
static inline bool aes_keysize_is_valid_and_not_null(JNIEnv *env, java_bytearray_ctx *key) {
    if (key->array == NULL) {
        throw_java_NPE(env, "key was null");
        return false;
    }
    switch (key->size) {
        case 16:
        case 24:
        case 32:
            return true;
        default:
            throw_java_illegal_argument(env, "key must be only 16,24 or 32 bytes long");
    }
    return false;
}

/**
 * Asserts key sizes but also accepts null keys.
 * This is used in cases where a null key is supplied because the implementation
 * is expected to use an old key but with a new iv.
 * @param env
 * @param key
 * @return
 */
static inline bool aes_keysize_is_valid_or_null(JNIEnv *env, java_bytearray_ctx *key) {
    if (key->array == NULL) {
        return true;
    }
    switch (key->size) {
        case 16:
        case 24:
        case 32:
            return true;
        default:
            throw_java_illegal_argument(env, "key must be only 16,24 or 32 bytes long");
    }
    return false;
}

/**
 * Asserts that for a single critical byte array that it is not null and the offset + len are within the bounds
 * of the critical array.
 * @param array the array to test
 * @param offset input offset
 * @param len length
 * @param env java env
 * @param beforeThrow
 * @return true if valid
 */
static inline bool
critical_offset_and_len_are_in_range(critical_bytearray_ctx *array, int offset, int len, JNIEnv *env) {
    if (offset < 0) {
        throw_java_illegal_argument(env, "offset is negative");
        return false;
    }

    if (len < 0) {
        throw_java_illegal_argument(env,
                                    "len is negative");
        return false;
    }

    if (!check_range(array->size, (size_t) offset, (size_t) len)) {
        throw_java_illegal_argument(env,
                                    "array too short for offset + len");
        return false;
    }

    return true;
}


/**
 * Assert single array, inOff >=0, len >=0, inOff+len <= array len for non critical byte array.
 *
 * This method does not assert java byte array is Null, if null all comparisons will be done on
 * as if it is a zero length array which may mislead callers,
 * java byte array is null assertion should be done before calling this.
 *
 * @param array  the array to test
 * @param inOff the input offset
 * @param len the length
 * @param env the java env
 * @return true if ok
 */
static inline bool bytearray_offset_and_len_are_in_range(java_bytearray_ctx *array, int inOff, int len, JNIEnv *env) {
    if (inOff < 0) {
        throw_java_illegal_argument(env, "offset is negative");
        return false;
    }

    if (len < 0) {
        throw_java_illegal_argument(env, "len is negative");
        return false;
    }


    if (!check_range(array->size, (size_t) inOff, (size_t) len)) {
        throw_java_illegal_argument(env,
                                    "array too short for offset + len");
        return false;
    }

    return true;
}

/**
 * Assert single array offset for critical byte array.
 *
 * This method does not assert java byte array is Null, if null all comparisons will be done on
 * as if it is a zero length array which may mislead callers,
 * java byte array is null assertion should be done before calling this.
 *
 * @param array  the array to test
 * @param offset the input offset
 * @param len the length
 * @param env the java env
 * @return true if ok
 */
static inline bool critical_offset_is_in_range(critical_bytearray_ctx *array, int offset, JNIEnv *env) {
    if (offset < 0) {
        throw_java_illegal_argument(env,
                                    "offset is negative");
        return false;
    }


    if (offset > array->size) {
        throw_java_illegal_argument(env, "offset past end of array");
        return false;
    }

    return true;
}

/**
 * Assert single array offset for non critical byte array.
 *
 * This method does not assert java byte array is Null, if null all comparisons will be done on
 * as if it is a zero length array which may mislead callers,
 * java byte array is null assertion should be done before calling this.
 *
 * @param array  the array to test
 * @param inOff the input offset
 * @param env the java env
 * @return true if ok
 */
static inline bool bytearray_offset_is_in_range(java_bytearray_ctx *array, int inOff, JNIEnv *env) {
    if (inOff < 0) {
        throw_java_illegal_argument(env, "offset is negative");
        return false;
    }

    if (inOff > array->size) {
        throw_java_illegal_argument(env, "offset past end of array");
        return false;
    }

    return true;
}


/**
 * Performs the process block input validation.
 * Returns false if there is an issue while throwing and exception.
 * @param env
 * @param input
 * @param output
 * @param inArray
 * @param inOffset
 * @param outArray
 * @param outOffset
 * @param blocks
 * @param blockSize
 * @param inStart pass by reference
 * @param outStart pass by reference
 * @return
 */
static inline bool block_processing_init(
        JNIEnv *env,
        critical_bytearray_ctx *input,
        critical_bytearray_ctx *output,
        jbyteArray inArray,
        jint inOffset,
        jbyteArray outArray,
        jint outOffset,
        int blocks,
        int blockSize,
        void **inStart, void **outStart) {



    //
    // Wrap but only grab lengths until we need the data.
    //
    init_critical_ctx(output, env, outArray);
    init_critical_ctx(input, env, inArray);

    if (!critical_not_null(output, "output was null", env)) {
        return false;
    }


    if (!critical_not_null(input, "input was null", env)) {
        return false;
    }


    if (!process_critical_blocks_valid(input, inOffset, blocks,
                                       output, outOffset, env, blockSize)) {
        return false;
    }

    //
    // out first
    //
    if (!load_critical_ctx(output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        return false;
    }

    if (!load_critical_ctx(input)) {
        release_critical_ctx(output);
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        return false;
    }


    *inStart = input->critical + inOffset;
    *outStart = output->critical + outOffset;

    return true;
}


/**
 * Performs the process block input validation.
 * Returns false if there is an issue while throwing an exception.
 * @param env
 * @param input
 * @param output
 * @param inArray
 * @param input_offset
 * @param outArray
 * @param output_offset
 * @param blocks
 * @param blockSize
 * @param inStart pass by reference
 * @param outStart pass by reference
 * @return
 */
static inline bool byte_processing_init(
        JNIEnv *env,
        critical_bytearray_ctx *input,
        critical_bytearray_ctx *output,
        jbyteArray inArray,
        jint input_offset,
        jbyteArray outArray,
        jint output_offset,
        int length,
        void **inStart, void **outStart) {



    //
    // Wrap but only extract java byte array lengths.
    // Critical access to data is requested after null, offsets and length are
    // verified against the lengths of the input and output arrays.
    //
    init_critical_ctx(output, env, outArray);
    init_critical_ctx(input, env, inArray);

    if (!critical_not_null(output, "output was null", env)) {
        return false;
    }

    if (!critical_not_null(input, "input was null", env)) {
        return false;
    }

    if (!input_and_output_critical_are_in_range_for_offsets_and_len(
            input,
            input_offset,
            length,
            output,
            output_offset,
            env)) {
        return false;
    }


    //
    // Here we request the JVM give us pointers to the array data within the JVM.
    // If the JVM is unable to do that we return false.
    // Given we have asserted length and null by this point the assumption is that the
    // JVM may be in an adverse state if it cannot supply a pointer to an otherwise valid byte array.
    //
    //
    // Callers to byte_processing_init are responsible for releasing the pointers back to the jvm after
    // they have finished accessing the data.
    //


    if (!load_critical_ctx(output)) {
        throw_java_invalid_state(env, "unable to obtain ptr to valid output array");
        return false;
    }

    if (!load_critical_ctx(input)) {
        release_critical_ctx(output);
        throw_java_invalid_state(env, "unable to obtain ptr to valid input array");
        return false;
    }


    //
    // By this point input_offset and output_offset have been tested as not negative and the
    // byte arrays on the java side are not null and long enough to contain the length.
    //

    *inStart = input->critical + input_offset;
    *outStart = output->critical + output_offset;

    return true;
}


#endif //BC_FIPS_JNI_ASSERTS_H
