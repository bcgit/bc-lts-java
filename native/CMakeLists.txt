cmake_minimum_required(VERSION 3.16)

FILE(TO_CMAKE_PATH "$ENV{JAVA_HOME}/include" JNI_INCLUDE)

#set(JNI_INCLUDE FILE(TO_CMAKE_PATH /include)

FILE(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/../core" FIPS_JAVA_ROOT)

message("JNI Include directory:  ${JNI_INCLUDE}")
message("FIPS_JAVA_ROOT  ${FIPS_JAVA_ROOT}")

option(LOG_LIFECYCLE "log lifecycle to std out" OFF)

if(${LOG_LIFECYCLE})
    set(LLCYCLE "LLCYCLE")
endif()

option(ENABLE_CODE_ANALYSIS "Run code analysis" OFF)

# We also need to include the machine dependent libraries.
set(JNI_INCLUDE_PLATFORM "")
set(LIBCRYPTO "")
set(JAVA_HEADERS ${FIPS_JAVA_ROOT}/build/generated/sources/headers/java/main)

set(CORE_NATIVE "bcn")
set(LIB_PROBE "bc-probe")
set(LIB_NATIVE "bc-components")


project(${CORE_NATIVE})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(NATIVE_INSTALL_ROOT ${CMAKE_SOURCE_DIR}/target)


set(VARIANT_PREFIX "unknown")
set(ASM_INCLUDE ${CMAKE_SOURCE_DIR}/intel/asm)

set(CMAKE_EXPORT_COMPILE_COMMANDS "ON")

string(TIMESTAMP BUILD_TS "%Y-%m-%dT%H:%M:%SZ")

if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")

    if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        MESSAGE("Building for Darwin Intel")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin/x86_64)
        set(ASM_DEFINES LINUX32E OSXEM64T)
        string(APPEND CMAKE_ASM_NASM_FLAGS "-g -i${ASM_INCLUDE}")
        set(CMAKE_ASM_NASM_OBJECT_FORMAT macho64)
        set(VARIANT_PREFIX "darwin-x86_64")
        set(OPTIONS -Wconversion)
    else ()
        MESSAGE("Building for Darwin ARM 64")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin/arm64)
        set(VARIANT_PREFIX "darwin-arm64")
        set(OPTIONS -Wconversion)
    endif ()


elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")


    if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")

        MESSAGE("Building for Linux Intel")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/linux)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/linux/x86_64)
        set(CMAKE_C_FLAGS "-std=c99")
        set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)
        set(ASM_DEFINES LINUX32E)
        string(APPEND CMAKE_ASM_NASM_FLAGS "-g -i${ASM_INCLUDE}")
        set(VARIANT_PREFIX "linux-x86_64")
        set(OPTIONS -Wconversion)
        set(PROBE_OPTIONS -O3 -msse4.1 ${OPTIONS})
        set(AVX_OPTIONS -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt ${OPTIONS})
        set(VAES_OPTIONS -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2  ${OPTIONS})
        set(VAESF_OPTIONS -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mavx512f -mavx512bw -mvpclmulqdq ${OPTIONS})

    else ()
        MESSAGE("Building for Windows Intel")
        FILE(TO_CMAKE_PATH "${JNI_INCLUDE}/win32" JNI_INCLUDE_PLATFORM)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/windows/x86_64)
        set(CMAKE_C_FLAGS "-std=c99")
        set(OPTIONS /Wall)
        set(PROBE_OPTIONS ${OPTIONS})
        set(SSE_OPTIONS ${OPTIONS})
        set(AVX_OPTIONS ${OPTIONS})
        set(VAES_OPTIONS /arch:AVX2  ${OPTIONS})
        set(VAESF_OPTIONS /arch:AVX512 ${OPTIONS})
    endif ()

endif ()


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src
        ${JNI_INCLUDE}
        ${JNI_INCLUDE_PLATFORM}
        ${JAVA_HEADERS}
        )


# Source sets


if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")

endif ()


set(VARIANTS sse)


#message(${CMAKE_ASM_NASM_FLAGS})
#enable_language(ASM_NASM)


#
# Common to both platforms
#

set(EXCEPTIONS
        exceptions/CipherTextException.cpp
        exceptions/CipherTextException.h
        exceptions/OutputLengthException.cpp
        exceptions/OutputLengthException.h
        )


#
# ARM
#
if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")

    set(JVM_UTIL_HEADERS jniutil/JavaEnvUtils.h jniutil/JavaByteArray.h)
    set(JVM_UTIL_IMPL jniutil/JavaByteArray.cpp jniutil/JavaEnvUtils.cpp)
    set(RAND_HEADERS arm64/jni/native_entropy_source_jni.cpp)
    set(RAND_IMPL)
    set(IDENT_IMPL arm64/jni/ident_jni.cpp arm64/jni/native_features.cpp arm64/rand/Rand.cpp)


    #
    # Probe project a simple lib for probing the CPUs features
    #
    add_library(${LIB_PROBE} SHARED arm64/jni/variant_selector.cpp)

    target_include_directories(${LIB_PROBE} PUBLIC ${JNI_INCLUDES})
    target_compile_options(${LIB_PROBE} PRIVATE $<$<COMPILE_LANGUAGE:CXX>: -mcpu=native+rng>)
    target_compile_definitions(${LIB_PROBE} PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\")
    install(TARGETS "${LIB_PROBE}" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


    add_library("${LIB_NATIVE}" SHARED

            ${RAND_HEADERS}
            ${RAND_IMPL}

            ${JVM_UTIL_HEADERS}
            ${JVM_UTIL_IMPL}

            ${IDENT_IMPL}

            )
    target_include_directories("${LIB_NATIVE}" PUBLIC ${JNI_INCLUDES})

    target_compile_options("${LIB_NATIVE}" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>: -mcpu=native+rng>
            $<$<COMPILE_LANGUAGE:C>: -mcpu=native+rng>
            )
    install(TARGETS "${LIB_NATIVE}" LIBRARY DESTINATION ${PLATFORM_TARGET}/components)
    target_compile_definitions("${LIB_NATIVE}" PUBLIC LOG_LIFECYCLE_=\"${LOG_LIFECYCLE}\" BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"arm64\" BUILD_TS=\"${BUILD_TS}\")

    add_executable(tryit main_arm.cpp ${DEBUG_FUNC})
    target_link_libraries(tryit "${LIB_NATIVE}")
    # -mcpu=native+rng
    target_compile_options("tryit" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>: -mcpu=native+rng>
            $<$<COMPILE_LANGUAGE:C>: -mcpu=native+rng>
            )


endif ()


if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(JVM_UTIL_HEADERS jniutil/JavaEnvUtils.h jniutil/JavaByteArray.h jniutil/JavaByteArrayCritical.h jniutil/JavaByteArrayCritical.cpp)
    set(JVM_UTIL_IMPL jniutil/JavaByteArray.cpp jniutil/JavaEnvUtils.cpp)
    set(RAND_HEADERS intel/rand/Rand.h)
    set(RAND_IMPL intel/rand/Rand.cpp intel/jni/native_entropy_source_jni.cpp)
    set(IDENT_IMPL intel/jni/ident_jni.cpp intel/jni/native_features.cpp)
    set(MACRO macro.h)
    set(COMMON intel/common.cpp intel/common.h intel/log.h)

    set(CBC
            intel/cbc/CBCLike.h
            intel/cbc/CBCLike.cpp
            intel/cbc/AesCBCEncrypt.cpp
            intel/cbc/AesCBCDecrypt.cpp
            intel/cbc/AesCBCNarrow.h
            intel/cbc/CBC128wide.cpp
            intel/cbc/CBC128wide.h
            intel/jni/cbc_jni.cpp)

    set(CBC_VAES
            intel/cbc/CBCLike.h
            intel/cbc/CBCLike.cpp
            intel/cbc/AesCBCEncrypt.cpp
            intel/cbc/AesCBCDecrypt.cpp
            intel/cbc/AesCBCNarrow.h
            intel/cbc/CBC128wide.cpp
            intel/cbc/CBC128wide.h
            intel/cbc/CBC256wide.cpp
            intel/cbc/CBC256wide.h
            intel/jni/cbc_jni_vaes.cpp
            intel/aes/aes_common_256b.h
            intel/aes/aes_common_128b.h
            intel/cbc/AesCBCDecryptVaes.cpp
            intel/cbc/AesCBCDecryptVaes.h
            )

    set(CBC_VAES_512f
            intel/cbc/CBCLike.h
            intel/cbc/CBCLike.cpp
            intel/cbc/CBC128wide.cpp
            intel/cbc/CBC128wide.h
            intel/cbc/AesCBCEncrypt.cpp
            intel/cbc/AesCBCDecryptVaesF.h
            intel/cbc/AesCBCDecryptVaesF.cpp
            intel/cbc/CBC512wide.cpp
            intel/cbc/CBC512wide.h
            intel/jni/cbc_jni_vaes_f.cpp
            intel/aes/aes_common_512b.h
            )


    set(CFB intel/cfb/CFBLike.h
            intel/cfb/CFBLike.cpp
            intel/cfb/AesCFB128Wide.h
            intel/cfb/AesCFBEncrypt.cpp
            intel/cfb/AesCFBDecrypt.cpp
            intel/cfb/CFB128Wide.cpp
            intel/cfb/CFB128Wide.h
            intel/jni/cfb_jni.cpp
            )

    set(CFB_VAES intel/cfb/CFBLike.h
            intel/cfb/CFBLike.cpp
            intel/cfb/AesCFB256Wide.h
            intel/cfb/AesCFBEncrypt.cpp
            intel/cfb/AesCFBDecrypt.cpp
            intel/cfb/AesCFBDecryptVAES.cpp
            intel/cfb/CFB256Wide.cpp
            intel/cfb/CFB256Wide.h
            intel/cfb/CFB128Wide.h
            intel/cfb/CFB128Wide.cpp
            intel/jni/cfb_jni_vaes.cpp
            )

    set(ECB intel/ecb/AesEcb.cpp
            intel/ecb/AesEcb.h
            intel/ecb/ecb.cpp
            intel/ecb/ecb.h
            intel/jni/ecb_jni.cpp
            intel/aes/aes_common_128b.h
            )

    set(ECB_VAES
            intel/ecb/AesEcb256W.h
            intel/ecb/AesEcb256W.cpp
            intel/ecb/ecb.cpp
            intel/ecb/ecb.h
            intel/jni/ecb_jni_vaes.cpp
            intel/aes/aes_common_256b.h
            )

    set(ECB_VAES_512f
            intel/ecb/AesEcb512W.h
            intel/ecb/AesEcb512W.cpp
            intel/ecb/ecb.cpp
            intel/ecb/ecb.h
            intel/jni/ecb_jni_vaesf.cpp
            intel/aes/aes_common_512b.h
            )

    set(GCM intel/jni/gcm_jni.cpp
            intel/gcm/AesGcm128wide.cpp
            intel/gcm/AesGcm128wide.h
            intel/gcm/gcm.cpp
            intel/gcm/gcm.h
            intel/gcm/ghash_128b.h)


    set(GCM_VAES intel/jni/gcm_jni_vaes.cpp
            intel/gcm/AesGcm256wide.cpp
            intel/gcm/AesGcm256wide.h
            intel/gcm/gcm.cpp
            intel/gcm/gcm.h)

    set(GCM_VAES_512f intel/jni/gcm_jni_vaesf.cpp
            intel/gcm/AesGcm512wide.cpp
            intel/gcm/AesGcm512wide.h
            intel/gcm/gcm.cpp
            intel/gcm/gcm.h
            intel/gcm/ghash_512b.h
            )

    set(DIGEST intel/digest/Digest.cpp
            intel/digest/Digest.h
            intel/digest/SHA256.cpp
            intel/digest/SHA256.h
            intel/jni/digest_jni.cpp
            )

    #
    # INTEL
    #

    #
    # Probe project a simple lib for probing the CPUs features
    #
    add_library(${LIB_PROBE} SHARED ${MACRO} intel/jni/variant_selector_intel.cpp)

    target_include_directories(${LIB_PROBE} PUBLIC ${JNI_INCLUDES})
    target_compile_options(${LIB_PROBE} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-O3 -msse4.1 ${OPTIONS}>)
    target_compile_definitions(${LIB_PROBE} PUBLIC ${LLCYCLE} BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\")
    install(TARGETS "${LIB_PROBE}" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


    add_library("${LIB_NATIVE}-sse" SHARED

            ${MACRO}
            ${COMMON}

            ${RAND_HEADERS}
            ${RAND_IMPL}

            ${JVM_UTIL_HEADERS}
            ${JVM_UTIL_IMPL}

            ${IDENT_IMPL}
            ${GCM}
            ${CBC}
            ${ECB}
            ${CFB}
            ${EXCEPTIONS}
            ${DIGEST}
            )
    target_include_directories("${LIB_NATIVE}-sse" PUBLIC ${JNI_INCLUDES})

    #
    # Intel
    #
    target_compile_options("${LIB_NATIVE}-sse" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-O3 -msse4.1 -msha -maes -mpclmul -mrdrnd -mrdseed ${OPTIONS}>
            $<$<COMPILE_LANGUAGE:C>:-O3 -msse4.1 -msha -maes -mpclmul -mrdrnd -mrdseed ${OPTIONS}>
            )
    install(TARGETS "${LIB_NATIVE}-sse" LIBRARY DESTINATION ${PLATFORM_TARGET}/sse)
    target_compile_definitions("${LIB_NATIVE}-sse" PUBLIC ${LLCYCLE} BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_SSE BC_VARIANT=\"sse\" BUILD_TS=\"${BUILD_TS}\")

    # specify the C++ standard
    add_library("${LIB_NATIVE}-avx" SHARED

            ${MACRO}
            ${COMMON}

            ${RAND_HEADERS}
            ${RAND_IMPL}

            ${JVM_UTIL_HEADERS}
            ${JVM_UTIL_IMPL}
            ${IDENT_IMPL}

            ${GCM}
            ${CBC}
            ${ECB}
            ${CFB}
            ${EXCEPTIONS}
            ${DIGEST}
            )
    target_include_directories("${LIB_NATIVE}-avx" PUBLIC ${JNI_INCLUDES})


    #Intel
    target_compile_options("${LIB_NATIVE}-avx" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:${AVX_OPTIONS}>
            $<$<COMPILE_LANGUAGE:C>:${AVX_OPTIONS}>
            )
    install(TARGETS "${LIB_NATIVE}-avx" LIBRARY DESTINATION ${PLATFORM_TARGET}/avx)
    target_compile_definitions("${LIB_NATIVE}-avx" PUBLIC ${LLCYCLE} BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_AVX BC_VARIANT=\"avx\" BUILD_TS=\"${BUILD_TS}\")

    #
    # VAES VERSION
    #
    add_library("${LIB_NATIVE}-vaes" SHARED

            ${MACRO}
            ${COMMON}

            ${RAND_HEADERS}
            ${RAND_IMPL}

            ${JVM_UTIL_HEADERS}
            ${JVM_UTIL_IMPL}
            ${IDENT_IMPL}

            ${GCM}
            ${CBC_VAES}
            ${ECB_VAES}
            ${CFB}
            ${EXCEPTIONS}
            ${DIGEST}
            )
    target_include_directories("${LIB_NATIVE}-vaes" PUBLIC ${JNI_INCLUDES})


    #
    #-mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 ${OPTIONS}
    #Intel
    target_compile_options("${LIB_NATIVE}-vaes" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:${VAES_OPTIONS} >
            $<$<COMPILE_LANGUAGE:C>:${VAES_OPTIONS}>
            )
    install(TARGETS "${LIB_NATIVE}-vaes" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaes)
    target_compile_definitions("${LIB_NATIVE}-vaes" PUBLIC ${LLCYCLE} BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VAES BC_VARIANT=\"vaes\" BC_VAES BUILD_TS=\"${BUILD_TS}\")

    #
    # VAES with AVX512F VERSION
    #
    add_library("${LIB_NATIVE}-vaesf" SHARED

            ${MACRO}
            ${COMMON}

            ${RAND_HEADERS}
            ${RAND_IMPL}

            ${JVM_UTIL_HEADERS}
            ${JVM_UTIL_IMPL}
            ${IDENT_IMPL}

            ${GCM_VAES}
            ${CBC_VAES_512f}
            ${ECB_VAES_512f}
            ${CFB_VAES}
            ${EXCEPTIONS}
            ${DIGEST}
            )
    target_include_directories("${LIB_NATIVE}-vaesf" PUBLIC ${JNI_INCLUDES})


    #
    #-mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 ${OPTIONS}
    #Intel
    target_compile_options("${LIB_NATIVE}-vaesf" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:${VAESF_OPTIONS} >
            $<$<COMPILE_LANGUAGE:C>:${VAESF_OPTIONS}>
    )
    install(TARGETS "${LIB_NATIVE}-vaesf" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaesf)
    target_compile_definitions("${LIB_NATIVE}-vaesf" PUBLIC ${LLCYCLE} BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VAESF BC_VARIANT=\"vaesf\" BC_VAES BUILD_TS=\"${BUILD_TS}\")

endif ()


#intel/gcm/gcm_func.cpp intel/gcm/gcm_func.h intel/gcm/gcm_intel.cpp intel/gcm/gcm_intel.h

##
## Test project
##

## Uncomment to enable test project
#add_executable(tryit main.cpp debug.h debug.cpp)
#target_link_libraries(tryit "${LIB_NATIVE}-vaesf")
#target_compile_options("tryit" PRIVATE $<$<COMPILE_LANGUAGE:CXX>: -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mavx512f -mgfni>
#        $<$<COMPILE_LANGUAGE:C>:-O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mavx512f -mgfni>)
#target_compile_definitions("tryit" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"vaes\" ${ASM_DEFINES} _ARCH_EM64T _L9)

###