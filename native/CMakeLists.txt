cmake_minimum_required(VERSION 3.16)

set(JNI_INCLUDE $ENV{JAVA_HOME}/include)
set(FIPS_JAVA_ROOT ${CMAKE_SOURCE_DIR}/../core)

message("JNI Include directory:  ${JNI_INCLUDE}")

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

if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")

    if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        MESSAGE("Building for Darwin Intel")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin/x86_64)
        set(ASM_DEFINES LINUX32E OSXEM64T)
        string(APPEND CMAKE_ASM_NASM_FLAGS "-g -i${ASM_INCLUDE}")
        set(CMAKE_ASM_NASM_OBJECT_FORMAT macho64)
        set(VARIANT_PREFIX "darwin-x86_64")
    else ()
        MESSAGE("Building for Darwin ARM 64")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin/arm64)
        set(VARIANT_PREFIX "darwin-arm64")
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
    else ()

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
    target_compile_definitions("${LIB_NATIVE}" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"arm64\")
endif ()


if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(JVM_UTIL_HEADERS jniutil/JavaEnvUtils.h jniutil/JavaByteArray.h jniutil/JavaByteArrayCritical.h jniutil/JavaByteArrayCritical.cpp )
    set(JVM_UTIL_IMPL jniutil/JavaByteArray.cpp jniutil/JavaEnvUtils.cpp)
    set(RAND_HEADERS intel/rand/Rand.h)
    set(RAND_IMPL intel/rand/Rand.cpp intel/jni/native_entropy_source_jni.cpp)
    set(IDENT_IMPL intel/jni/ident_jni.cpp intel/jni/native_features.cpp)
    set(COMMON intel/common.cpp intel/common.h)
    set(CBC intel/cbc/AesCBC128Impl.cpp
            intel/cbc/AesCBC192Impl.cpp
            intel/cbc/AesCBC256Impl.cpp
            intel/cbc/AesCBC.h
            intel/cbc/CBC.cpp
            intel/cbc/CBC.h
            intel/jni/cbc_jni.cpp)

    set(CFB intel/cfb/AesCFB.h
            intel/cfb/AesCFB128Impl.cpp
            intel/cfb/AesCFB192Impl.cpp
            intel/cfb/AesCFB256Impl.cpp
            intel/cfb/cfb.cpp
            intel/cfb/cfb.h
            intel/jni/cfb_jni.cpp
            )

    set(ECB intel/ecb/AesEcb.cpp
            intel/ecb/AesEcb.h
            intel/ecb/ecb.cpp
            intel/ecb/ecb.h
            intel/jni/ecb_jni.cpp
            )

    set(GCM intel/jni/gcm_jni.cpp
            intel/gcm/AesGcm.cpp
            intel/gcm/AesGcm.h
            intel/gcm/gcm.cpp
            intel/gcm/gcm.h)


    #
    # INTEL
    #

    #
    # Probe project a simple lib for probing the CPUs features
    #
    add_library(${LIB_PROBE} SHARED intel/jni/variant_selector_intel.cpp)

    target_include_directories(${LIB_PROBE} PUBLIC ${JNI_INCLUDES})
    target_compile_options(${LIB_PROBE} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-O3 -msse4.1>)
    target_compile_definitions(${LIB_PROBE} PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\")
    install(TARGETS "${LIB_PROBE}" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


    add_library("${LIB_NATIVE}-sse" SHARED

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
            )
    target_include_directories("${LIB_NATIVE}-sse" PUBLIC ${JNI_INCLUDES})

    #
    # Intel
    #
    target_compile_options("${LIB_NATIVE}-sse" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-O3 -msse4.1 -msha -maes -mpclmul -mrdrnd -mrdseed>
            $<$<COMPILE_LANGUAGE:C>:-O3 -msse4.1 -msha -maes -mpclmul -mrdrnd -mrdseed>
            )
    install(TARGETS "${LIB_NATIVE}-sse" LIBRARY DESTINATION ${PLATFORM_TARGET}/sse)
    target_compile_definitions("${LIB_NATIVE}-sse" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"sse\")


    # specify the C++ standard
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed")
    add_library("${LIB_NATIVE}-avx" SHARED

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
            )
    target_include_directories("${LIB_NATIVE}-avx" PUBLIC ${JNI_INCLUDES})


    #Intel
    target_compile_options("${LIB_NATIVE}-avx" PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt>
            $<$<COMPILE_LANGUAGE:C>:-O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt>
            )
    install(TARGETS "${LIB_NATIVE}-avx" LIBRARY DESTINATION ${PLATFORM_TARGET}/avx)
    target_compile_definitions("${LIB_NATIVE}-avx" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"avx\")
endif ()

#
## specify the C++ standard
##set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed")
#add_library("${LIB_NATIVE}-vaes" SHARED
#        ${IPPC_C}
#        ${INTEL_ASM}
#
#        ${PROBE_HEADERS}
#        ${PROBE_IMPL}
#        ${RAND_HEADERS}
#        ${RAND_IMPL}
#
#        ${JVM_UTIL_HEADERS}
#        ${JVM_UTIL_IMPL}
#
#        ${GCM_HEADERS}
#        ${GCM_IMPL}
#
#        ${ECB_HEADERS}
#        ${ECB_IMPL}
#
#        ${AES_FUNC}
#        ${CT_FUNC}
#
#        ${EXCEPTIONS}
#
#        ${DEBUG_FUNC}
#        ${CBC_HEADERS}
#        ${CBC_IMPL}
#
#        ${DIGEST_HEADERS}
#        ${DIGEST_IMPL}
#
#        ${IDENT_IMPL}
#        )
#target_include_directories("${LIB_NATIVE}-vaes" PUBLIC ${JNI_INCLUDES})
##target_link_libraries("${LIB_NATIVE}-vaes" ${LIB_PROBE})
#target_compile_options("${LIB_NATIVE}-vaes" PRIVATE -O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mvaes)
#install(TARGETS "${LIB_NATIVE}-vaes" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaes)
#target_compile_definitions("${LIB_NATIVE}-vaes" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"vaes\" BC_VAES ${ASM_DEFINES})
#
#


#intel/gcm/gcm_func.cpp intel/gcm/gcm_func.h intel/gcm/gcm_intel.cpp intel/gcm/gcm_intel.h

##
## Test project
##

## Uncomment to enable test project
#add_executable(tryit main.cpp ${DEBUG_FUNC})
#target_link_libraries(tryit "${LIB_NATIVE}-avx")
#target_compile_options("tryit" PRIVATE $<$<COMPILE_LANGUAGE:CXX>: -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt> $<$<COMPILE_LANGUAGE:C>:-O3 -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt>)
#target_compile_definitions("tryit" PUBLIC BC_VARIANT_PREFIX=\"${VARIANT_PREFIX}\" BC_VARIANT=\"avx\" ${ASM_DEFINES} _ARCH_EM64T _L9)

###