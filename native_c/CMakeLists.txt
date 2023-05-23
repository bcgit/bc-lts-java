cmake_minimum_required(VERSION 3.16)

FILE(TO_CMAKE_PATH "$ENV{JAVA_HOME}/include" JNI_INCLUDE)

FILE(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/../core" FIPS_JAVA_ROOT)

message("JNI Include directory:  ${JNI_INCLUDE}")
message("FIPS_JAVA_ROOT  ${FIPS_JAVA_ROOT}")

# We also need to include the machine dependent libraries.
set(JNI_INCLUDE_PLATFORM "")
set(LIBCRYPTO "")
set(FIPS_JAVA_HEADERS ${FIPS_JAVA_ROOT}/build/generated/sources/headers/java/main)

option(ENABLE_CODE_ANALYSIS "Run code analysis" OFF)

set(CORE_NATIVE "bc-lts-c")
set(LIB_PROBE "bc-probe")
set(LIB_NATIVE "bc-lts")

string(TIMESTAMP BUILD_TS "%Y-%m-%dT%H:%M:%S")


project(${CORE_NATIVE} LANGUAGES C)
enable_language(ASM_NASM)
set(NATIVE_INSTALL_ROOT ${CMAKE_SOURCE_DIR}/target)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        MESSAGE("Building for Linux Intel")

        set(OPTIMISE_FLAG -O3)
        # Test for dev environment.
        # If dev environment variable LTS_DEV exists then turn off optimisations and switch on debugging
        #
        if (DEFINED ENV{LTS_DEV})
            set(OPTIMISE_FLAG -g)
            MESSAGE("DEBUG BUILD --- NOT OPTIMISED")
        else ()
            MESSAGE("RELEASE BUILD --- OPTIMISED")
        endif ()


        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/linux)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/linux/x86_64)
        set(CMAKE_C_FLAGS "-std=c99")
        set(OPTIONS -Wconversion -static-libgcc -z noexecstack)
        set(PROBE_OPTIONS ${OPTIMISE_FLAG} -msse4.1 ${OPTIONS})
        set(AVX_OPTIONS ${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt ${OPTIONS})
        set(VAES_OPTIONS ${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 ${OPTIONS})
        set(VAESF_OPTIONS ${OPTIMISE_FLAG} -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mavx512f -mavx512bw -mvpclmulqdq ${OPTIONS})
        set(ASM_OPTIONS -f elf64)
        set(COMMON_ASM intel/common_sysV.asm)
    endif ()
else ()
    MESSAGE("Building for Windows Intel")
    FILE(TO_CMAKE_PATH "${JNI_INCLUDE}/win32" JNI_INCLUDE_PLATFORM)
    set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/windows/x86_64)
    set(CMAKE_C_FLAGS "-std=c99")
    set(OPTIONS /Wall)
    set(PROBE_OPTIONS ${OPTIONS})
    set(SSE_OPTIONS ${OPTIONS})
    set(AVX_OPTIONS ${OPTIONS})
    set(VAES_OPTIONS /arch:AVX2 ${OPTIONS})
    set(VAESF_OPTIONS /arch:AVX512 ${OPTIONS})

endif ()

MESSAGE("JNI_INCLUDE_PLATFORM" ${JNI_INCLUDE_PLATFORM})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src ${JNI_INCLUDE} ${JNI_INCLUDE_PLATFORM} ${FIPS_JAVA_HEADERS})


set(PROBE intel/jni/variant_selector_intel.c)
set(IDENT_IMPL intel/jni/ident_jni.c intel/jni/native_features.c)
set(COMMON intel/common.c intel/common.h ${COMMON_ASM})
set(JNI_UTIL
        jniutil/bytearrays.h
        jniutil/bytearrays.c
        jniutil/bytearraycritical.c
        jniutil/bytearraycritical.h
        jniutil/exceptions.c
        jniutil/exceptions.h
        jniutil/jni_asserts.h
        )


set(ECB
        intel/jni/ecb_jni.c
        intel/ecb/ecb128w.c
        intel/ecb/ecb.h
        intel/ecb/ecb.c)

set(ECB_VAES
        intel/jni/ecb_jni.c
        intel/ecb/ecb256w.c
        intel/ecb/ecb.h
        intel/ecb/ecb.c)

set(ECB_VAESF
        intel/jni/ecb_jni.c
        intel/ecb/ecb512w.c
        intel/ecb/ecb.h
        intel/ecb/ecb.c)

set(CBC
        intel/cbc/cbc.h
        intel/cbc/cbc.c
        intel/cbc/cbc128.c
        intel/jni/cbc_jni.c
        )

set(CBC_VAES
        intel/cbc/cbc.h
        intel/cbc/cbc.c
        intel/cbc/cbc256.c
        intel/jni/cbc_jni.c
        )

set(CBC_VAESF
        intel/cbc/cbc.h
        intel/cbc/cbc.c
        intel/cbc/cbc512.c
        intel/jni/cbc_jni.c
        )


set(CFB
        intel/cfb/cfb.h
        intel/cfb/cfb.c
        intel/cfb/cfb128.c
        intel/jni/cfb_jni.c
        )

set(CFB_VAES
        intel/cfb/cfb.h
        intel/cfb/cfb.c
        intel/cfb/cfb256.c
        intel/jni/cfb_jni.c
        )

set(CFB_VAESF
        intel/cfb/cfb.h
        intel/cfb/cfb.c
        intel/cfb/cfb512.c
        intel/jni/cfb_jni.c
        )

set(CTR
        intel/ctr/ctr.h
        intel/ctr/ctr.c
        intel/ctr/ctr128w.c
        intel/jni/ctr_jni.c
        )


set(CTR_VAES
        intel/ctr/ctr.h
        intel/ctr/ctr.c
        intel/ctr/ctr256w.c
        intel/jni/ctr_jni.c
        )

set(CTR_VAESF
        intel/ctr/ctr.h
        intel/ctr/ctr.c
        intel/ctr/ctr512w.c
        intel/jni/ctr_jni.c
        )

set (RAND intel/jni/rand_jni.c)

set (SHA256
        intel/sha/sha256.c
        intel/sha/sha256.h
        intel/jni/sha256_jni.c
        )

set (GCM
        intel/gcm/gcm.h
        intel/gcm/gcm.c
        intel/gcm/gcmHash128.h
        intel/gcm/gcm128w.c
        intel/jni/gcm_jni.c
        )

set (GCM_VAESF
        intel/gcm/gcm.h
        intel/gcm/gcm.c
        intel/gcm/gcmHash512.h
        intel/gcm/gcm512w.c
        intel/jni/gcm_jni.c
        )


# Probe project a simple lib for probing the CPUs features
#
add_library(${LIB_PROBE} SHARED ${PROBE})

target_include_directories(${LIB_PROBE} PUBLIC ${JNI_INCLUDES})
target_compile_options(${LIB_PROBE} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${PROBE_OPTIONS}>)
target_compile_definitions(${LIB_PROBE} PUBLIC BUILD_TS=\"${BUILD_TS}\")
install(TARGETS "${LIB_PROBE}" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


#
# AVX variant
#

add_library(${LIB_NATIVE}-avx SHARED
        ${COMMON}
        ${JNI_UTIL}
        ${IDENT_IMPL}
        ${ECB}
        ${CBC}
        ${CFB}
        ${CTR}
        ${RAND}
        ${SHA256}
        ${GCM}
        )
target_include_directories("${LIB_NATIVE}-avx" PUBLIC ${JNI_INCLUDES})
target_compile_options("${LIB_NATIVE}-avx" PRIVATE $<$<COMPILE_LANGUAGE:C>:${AVX_OPTIONS}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
install(TARGETS "${LIB_NATIVE}-avx" LIBRARY DESTINATION ${PLATFORM_TARGET}/avx)
target_compile_definitions("${LIB_NATIVE}-avx" PUBLIC BC_AVX BC_VARIANT=\"avx\" BUILD_TS=\"${BUILD_TS}\")


add_library(${LIB_NATIVE}-vaes SHARED
        ${COMMON}
        ${JNI_UTIL}
        ${IDENT_IMPL}
        ${ECB_VAES}
        ${CBC_VAES}
        ${CFB_VAES}
        ${CTR_VAES}
        ${RAND}
        ${SHA256}
        ${GCM}
        )
target_include_directories("${LIB_NATIVE}-vaes" PUBLIC ${JNI_INCLUDES})
target_compile_options("${LIB_NATIVE}-vaes" PRIVATE $<$<COMPILE_LANGUAGE:C>:${VAES_OPTIONS}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
install(TARGETS "${LIB_NATIVE}-vaes" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaes)
target_compile_definitions("${LIB_NATIVE}-vaes" PUBLIC BC_VAES BC_VARIANT=\"vaes\" BUILD_TS=\"${BUILD_TS}\")


add_library(${LIB_NATIVE}-vaesf SHARED
        ${COMMON}
        ${JNI_UTIL}
        ${IDENT_IMPL}
        ${ECB_VAESF}
        ${CBC_VAESF}
        ${CFB_VAESF}
        ${CTR_VAESF}
        ${RAND}
        ${SHA256}
        ${GCM_VAESF}
        )
target_include_directories("${LIB_NATIVE}-vaesf" PUBLIC ${JNI_INCLUDES})
target_compile_options("${LIB_NATIVE}-vaesf" PRIVATE $<$<COMPILE_LANGUAGE:C>:${VAESF_OPTIONS}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
install(TARGETS "${LIB_NATIVE}-vaesf" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaesf)
target_compile_definitions("${LIB_NATIVE}-vaesf" PUBLIC BC_VAESF BC_VARIANT=\"vaesf\" BUILD_TS=\"${BUILD_TS}\")


# Uncomment to enable test project
#add_executable(tryit main.c debug.h)
#target_link_libraries(tryit "${LIB_NATIVE}-vaesf")
#target_compile_options("tryit" PRIVATE
#        $<$<COMPILE_LANGUAGE:C>: -Wpsabi -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mvpclmulqdq -mavx512f -mavx512bw ${OPTIONS}>
#        )
