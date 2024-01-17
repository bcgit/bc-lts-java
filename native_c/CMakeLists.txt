cmake_minimum_required(VERSION 3.16)

FILE(TO_CMAKE_PATH "$ENV{JAVA_HOME}/include" JNI_INCLUDE)

FILE(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/../core" FIPS_JAVA_ROOT)

message("JNI Include directory:  ${JNI_INCLUDE}")
message("FIPS_JAVA_ROOT  ${FIPS_JAVA_ROOT}")

message("Looking for either JAVA_HOME or LTS_JDK8 env vars. ")

if (DEFINED ENV{JAVA_HOME})
    message("Found JAVA_HOME..")
    FILE(TO_CMAKE_PATH "$ENV{JAVA_HOME}/include" JNI_INCLUDE)
else ()
    message("Found LTS_JDK8..")
    FILE(TO_CMAKE_PATH "$ENV{LTS_JDK8}/include" JNI_INCLUDE)
endif ()



FILE(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/../core" LTS_JAVA_ROOT)

message("JNI Include directory:  ${JNI_INCLUDE}")
message("LTS_JAVA_ROOT: ${LTS_JAVA_ROOT}")

# We also need to include the machine dependent libraries.
set(JNI_INCLUDE_PLATFORM "")
set(LIBCRYPTO "")
set(LTS_JAVA_HEADERS ${LTS_JAVA_ROOT}/build/generated/sources/headers/java/main)
set(LTS_TEST_JAVA_HEADERS ${LTS_JAVA_ROOT}/build/generated/sources/headers/java/test)
message("LTS_JAVA_HEADERS: " ${LTS_JAVA_HEADERS})

option(ENABLE_CODE_ANALYSIS "Run code analysis" OFF)

set(CORE_NATIVE "bc-lts-c")
set(LIB_PROBE "bc-probe")
set(LIB_NATIVE "bc-lts")

string(TIMESTAMP BUILD_TS "%Y-%m-%dT%H:%M:%S")


project(${CORE_NATIVE} LANGUAGES C)

set(NATIVE_INSTALL_ROOT ${CMAKE_SOURCE_DIR}/target)


#
# Common sources between all CPUs
#

set(JNI_UTIL
        jniutil/bytearrays.h
        jniutil/bytearrays.c
        jniutil/bytearraycritical.c
        jniutil/bytearraycritical.h
        jniutil/exceptions.c
        jniutil/exceptions.h
        jniutil/jni_asserts.h
        jniutil/longarrays.c
        jniutil/longarrays.h
        jniutil/longarraycritical.c
        jniutil/longarraycritical.h
        jniutil/variant_selector.h
        )


if ((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64") OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64"))


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

    if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
        message("Detected OSX Darwin")

        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/darwin)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/darwin/arm64)
        set(OPTIONS -Wconversion -Werror=return-type)
        set(PROBE_OPTIONS ${OPTIMISE_FLAG})
        set(ARM64_NEON_OPTIONS ${OPTIONS} ${OPTIMISE_FLAG})

    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        message("Detected Linux")
        set(JNI_INCLUDE_PLATFORM ${JNI_INCLUDE}/linux)
        set(PLATFORM_TARGET ${NATIVE_INSTALL_ROOT}/linux/arm64)
        set(OPTIONS -Wconversion -Werror=return-type)
        set(PROBE_OPTIONS ${OPTIMISE_FLAG})
        set(ARM64_NEON_OPTIONS ${OPTIONS} -march=armv8.4-a+crypto+sha2+sha3 ${OPTIMISE_FLAG})
        set(ARM_BE -mbig-endian)
    endif ()

    MESSAGE("JNI_INCLUDE_PLATFORM " ${JNI_INCLUDE_PLATFORM})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src ${JNI_INCLUDE} ${JNI_INCLUDE_PLATFORM} ${LTS_JAVA_HEADERS} ${LTS_TEST_JAVA_HEADERS})

    set(PROBE arm/jni/variant_selector_arm.c)
    set(COMMON arm/jni/native_features.c arm/jni/ident_jni.c arm/util/util.h arm/util/util.c)
    set(COMMON_NEON
            arm/aes/aes_common_neon.h
            arm/aes/aes_key.c
            arm/aes/schedule.h
            arm/keccak/keccak.h
            )

    set(ARM_ECB arm/jni/ecb_jni.c arm/ecb/ecb.h arm/ecb/ecb_neon.c jniutil/variant_selector.h)

    set(ARM_GCM
            arm/jni/gcm_jni.c
            arm/gcm/gcm.h
            arm/gcm/gcm.c
            arm/gcm/gcm_hash.h
            arm/gcm/gcm_aes_func.h
            arm/gcm/gcm_neon.c
            )

    set(ARM_CBC
            arm/cbc/cbc.h
            arm/cbc/cbc.c
            arm/cbc/cbc_neon.c
            arm/jni/cbc_jni.c
            )

    set(ARM_CFB
            arm/cfb/cfb.h
            arm/cfb/cfb.c
            arm/cfb/cfb_neon.c
            arm/jni/cfb_jni.c
            )

    set(ARM_CTR
            arm/jni/ctr_jni.c
            arm/ctr/ctr.h
            arm/ctr/ctr.c
            arm/ctr/ctr_neon.c
            )

    set(ARM_CCM
            arm/jni/ccm_jni.c
            arm/ccm/ccm.h
            arm/ccm/ccm.c
            arm/ccm/ccm_neon.c
            )

    set(ARM_SHA256
            arm/sha/sha256.h
            arm/sha/sha256.c
            arm/jni/sha256_jni.c
            )

    set(ARM_SHA256
            arm/sha/sha256.h
            arm/sha/sha256.c
            arm/jni/sha256_jni.c
            )

    set(ARM_SHA224
            arm/sha/sha224.h
            arm/sha/sha224.c
            arm/jni/sha224_jni.c
            )

    set(ARM_SHA384
            arm/sha/sha384.h
            arm/sha/sha384.c
            arm/jni/sha384_jni.c
            )

    set(ARM_SHA512
            arm/sha/sha512.h
            arm/sha/sha512.c
            arm/jni/sha512_jni.c
            )

    set(ARM_SHA3
            arm/sha/sha3.h
            arm/sha/sha3.c
            arm/jni/sha3_jni.c
            )

    set(ARM_SHAKE
            arm/sha/shake.h
            arm/sha/shake.c
            arm/jni/shake_jni.c
            )

    set(ARM_MUL
            arm/mul/cmul.h
            arm/mul/cmul128.c
            arm/jni/cmul_jni.c
            )

    add_library(${LIB_PROBE}-le SHARED ${PROBE})
    target_include_directories(${LIB_PROBE}-le PUBLIC ${JNI_INCLUDES})
    target_compile_options(${LIB_PROBE}-le PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${PROBE_OPTIONS}>)
    target_compile_definitions(${LIB_PROBE}-le PUBLIC BUILD_TS=\"${BUILD_TS}\")
    install(TARGETS "${LIB_PROBE}-le" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


    #
    # Arm projects LE
    #
    add_library(${LIB_NATIVE}-neon-le SHARED
            ${JNI_UTIL}
            ${COMMON}
            ${COMMON_NEON}
            ${ARM_ECB}
            ${ARM_GCM}
            ${ARM_CBC}
            ${ARM_CFB}
            ${ARM_CTR}
            ${ARM_CCM}
            ${ARM_SHA256}
            ${ARM_SHA224}
            ${ARM_SHA384}
            ${ARM_SHA512}
            ${ARM_SHA3}
            ${ARM_SHAKE}
            ${ARM_MUL}
            )
    target_include_directories("${LIB_NATIVE}-neon-le" PUBLIC ${JNI_INCLUDES})
    target_compile_options("${LIB_NATIVE}-neon-le" PRIVATE $<$<COMPILE_LANGUAGE:C>:${ARM64_NEON_OPTIONS}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
    install(TARGETS "${LIB_NATIVE}-neon-le" LIBRARY DESTINATION ${PLATFORM_TARGET}/neon-le)
    target_compile_definitions("${LIB_NATIVE}-neon-le" PUBLIC BC_NEON BC_VARIANT=\"neon-le\" BUILD_TS=\"${BUILD_TS}\")


                # A Linux issue.
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

        #
        # Big Endian compile targets
        #

#        add_library(${LIB_PROBE}-be SHARED ${PROBE})
#        target_include_directories(${LIB_PROBE}-be PUBLIC ${JNI_INCLUDES})
#        target_compile_options(${LIB_PROBE}-be PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${PROBE_OPTIONS} -mbig-endian>)
#        target_compile_definitions(${LIB_PROBE}-be PUBLIC BUILD_TS=\"${BUILD_TS}\")
#        install(TARGETS "${LIB_PROBE}-be" LIBRARY DESTINATION ${PLATFORM_TARGET}/probe)


#        add_library(${LIB_NATIVE}-neon-be SHARED
#                ${JNI_UTIL}
#                ${COMMON}
#                ${COMMON_NEON}
#                ${ARM_ECB}
#                ${ARM_GCM}
#                ${ARM_CBC}
#                ${ARM_CFB}
#                ${ARM_CTR}
#                ${ARM_CCM}
#                ${ARM_SHA256}
#                )
#        target_include_directories("${LIB_NATIVE}-neon-be" PUBLIC ${JNI_INCLUDES})
#        target_compile_options("${LIB_NATIVE}-neon-be" PRIVATE $<$<COMPILE_LANGUAGE:C>:${ARM64_NEON_OPTIONS} ${ARM_BE}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
#        install(TARGETS "${LIB_NATIVE}-neon-be" LIBRARY DESTINATION ${PLATFORM_TARGET}/neon-be)
#        target_compile_definitions("${LIB_NATIVE}-neon-be" PUBLIC BC_NEON BC_VARIANT=\"neon\" BUILD_TS=\"${BUILD_TS}\")
    endif ()

    #
    # Main method for testing.
    #
    #  add_executable("tryit" main.c debug_neon.h)
    #  target_link_libraries("tryit" ${LIB_NATIVE}-neon-le)



else ()
    #
    # Intel setup
    #
    enable_language(ASM_NASM)


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
            set(OPTIONS -Wconversion -Werror=return-type -static-libgcc -z noexecstack)
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
    include_directories(
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${JNI_INCLUDE}
            ${JNI_INCLUDE_PLATFORM}
            ${LTS_JAVA_HEADERS}
            ${LTS_TEST_JAVA_HEADERS})


    set(PROBE intel/jni/variant_selector_intel.c)
    set(IDENT_IMPL intel/jni/ident_jni.c intel/jni/native_features.c)
    set(COMMON intel/common.c intel/common.h intel/util/util.c intel/util/util.h ${COMMON_ASM})


    set(MUL_AVX intel/jni/cmul_jni.c intel/mul/cmul.h intel/mul/cmul128.c)
    set(MUL_VAESF intel/jni/cmul_jni.c intel/mul/cmul.h intel/mul/cmul128.c)


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

    set(CBC_PC
            intel/packet/cbc_pc/cbc_pc.h
            intel/packet/cbc_pc/cbc_pc.c
            intel/packet/cbc_pc/cbc_pc128.c
            intel/jni/cbc_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(CBC_PC_VAES
            intel/packet/cbc_pc/cbc_pc.h
            intel/packet/cbc_pc/cbc_pc.c
            intel/packet/cbc_pc/cbc_pc256.c
            intel/jni/cbc_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(CBC_PC_VAESF
            intel/packet/cbc_pc/cbc_pc.h
            intel/packet/cbc_pc/cbc_pc.c
            intel/packet/cbc_pc/cbc_pc512.c
            intel/jni/cbc_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
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

    set(CFB_PC
            intel/packet/cfb_pc/cfb_pc.h
            intel/packet/cfb_pc/cfb_pc.c
            intel/packet/cfb_pc/cfb_pc128.c
            intel/jni/cfb_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(CFB_PC_VAES
            intel/packet/cfb_pc/cfb_pc.h
            intel/packet/cfb_pc/cfb_pc.c
            intel/packet/cfb_pc/cfb_pc256.c
            intel/jni/cfb_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(CFB_PC_VAESF
            intel/packet/cfb_pc/cfb_pc.h
            intel/packet/cfb_pc/cfb_pc.c
            intel/packet/cfb_pc/cfb_pc512.c
            intel/jni/cfb_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
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

    set(CTR_PC
            intel/packet/ctr_pc/ctr_pc.h
            intel/packet/ctr_pc/ctr_pc.c
            intel/packet/ctr_pc/ctr_pc128w.c
            intel/jni/ctr_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
    )

    set(CTR_PC_VAES
            intel/packet/ctr_pc/ctr_pc.h
            intel/packet/ctr_pc/ctr_pc.c
            intel/packet/ctr_pc/ctr_pc256w.c
            intel/jni/ctr_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
    )

    set(CTR_PC_VAESF
            intel/packet/ctr_pc/ctr_pc.h
            intel/packet/ctr_pc/ctr_pc.c
            intel/packet/ctr_pc/ctr_pc512w.c
            intel/jni/ctr_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
    )

    set(RAND intel/jni/rand_jni.c)

    set(SHA256
            intel/sha/sha256.c
            intel/sha/sha256.h
            intel/jni/sha256_jni.c
            )

    set(SHA224
            intel/sha/sha224.c
            intel/sha/sha224.h
            intel/jni/sha224_jni.c
            )

    set(GCM
            intel/gcm/gcm.h
            intel/gcm/gcm.c
            intel/gcm/gcmHash128.h
            intel/gcm/gcm128w.c
            intel/jni/gcm_jni.c
            )

    set(GCM_VAESF
            intel/gcm/gcm.h
            intel/gcm/gcm.c
            intel/gcm/gcmHash512.h
            intel/gcm/gcm512w.c
            intel/jni/gcm_jni.c
            )
    set(GCM_PC
            intel/packet/gcm_pc/gcm_pc.h
            intel/packet/gcm_pc/gcm_pc.c
            intel/packet/gcm_pc/gcm_pcHash128.h
            intel/packet/gcm_pc/gcm_pc128w.c
            intel/jni/gcm_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(GCM_PC_VAESF
            intel/packet/gcm_pc/gcm_pc.h
            intel/packet/gcm_pc/gcm_pc.c
            intel/packet/gcm_pc/gcm_pcHash512.h
            intel/packet/gcm_pc/gcm_pc512w.c
            intel/jni/gcm_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(GCM_SIV
            intel/gcm_siv/gcm_siv.h
            intel/gcm_siv/gcm_siv.c
            intel/jni/gcm_siv_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )

    set(GCM_SIV_PC
            intel/gcm_siv/gcm_siv.h
            intel/gcm_siv/gcm_siv.c
            intel/packet/gcm_siv_pc/gcm_siv_pc.h
            intel/packet/gcm_siv_pc/gcm_siv_pc.c
            intel/jni/gcm_siv_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
    )


    set(CCM
            intel/ccm/ccm.h
            intel/ccm/ccm.c
            intel/ccm/ccm128.c
            intel/jni/ccm_jni.c)

    set(CCM_VAES
            intel/ccm/ccm.h
            intel/ccm/ccm.c
            intel/ccm/ccm256.c
            intel/jni/ccm_jni.c
            )

    set(CCM_VAESF
            intel/ccm/ccm.h
            intel/ccm/ccm.c
            intel/ccm/ccm512.c
            intel/jni/ccm_jni.c
            )

    set(CCM_PC
             intel/packet/ccm_pc/ccm_pc.h
             intel/packet/ccm_pc/ccm_pc.c
             intel/packet/ctr_pc/ctr_pc128w.c
             intel/jni/ccm_pc_jni.c
             intel/packet/packet_utils.h
             intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
            )

    set(CCM_PC_VAES
            intel/packet/ccm_pc/ccm_pc.h
            intel/packet/ccm_pc/ccm_pc.c
            intel/packet/ctr_pc/ctr_pc256w.c
            intel/jni/ccm_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
    )

    set(CCM_PC_VAESF
            intel/packet/ccm_pc/ccm_pc.h
            intel/packet/ccm_pc/ccm_pc.c
            intel/packet/ctr_pc/ctr_pc512w.c
            intel/jni/ccm_pc_jni.c
            intel/packet/packet_utils.h
            intel/packet/packet_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.c
            intel/packet/ctr_pc/ctr_pc_utils.h
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
            ${CBC_PC}
            ${CFB}
            ${CFB_PC}
            ${CTR}
            ${CTR_PC}
            ${RAND}
            ${SHA256}
            ${GCM}
            ${GCM_PC}
            ${GCM_SIV}
            ${GCM_SIV_PC}
            ${MUL_AVX}
            ${CCM}
            ${CCM_PC}
            ${SHA224}
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
            ${CBC_PC_VAES}
            ${CFB_VAES}
            ${CFB_PC_VAES}
            ${CTR_VAES}
            ${CTR_PC_VAES}
            ${RAND}
            ${SHA256}
            ${GCM}
            ${GCM_PC}
            ${GCM_SIV}
            ${GCM_SIV_PC}
            ${MUL_AVX}
            ${CCM_PC_VAES}
            ${CCM_VAES}
            ${SHA224}
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
            ${CBC_PC_VAESF}
            ${CFB_VAESF}
            ${CFB_PC_VAESF}
            ${CTR_VAESF}
            ${CTR_PC_VAESF}
            ${RAND}
            ${SHA256}
            ${GCM_VAESF}
            ${GCM_PC_VAESF}
            ${GCM_SIV}
            ${GCM_SIV_PC}
            ${MUL_VAESF}
            ${CCM_VAESF}
            ${CCM_PC_VAESF}
            ${SHA224}
            )
    target_include_directories("${LIB_NATIVE}-vaesf" PUBLIC ${JNI_INCLUDES})
    target_compile_options("${LIB_NATIVE}-vaesf" PRIVATE $<$<COMPILE_LANGUAGE:C>:${VAESF_OPTIONS}> $<$<COMPILE_LANGUAGE:ASM>: ${ASM_OPTIONS} ${ASM_FLAGS}>)
    install(TARGETS "${LIB_NATIVE}-vaesf" LIBRARY DESTINATION ${PLATFORM_TARGET}/vaesf)
    target_compile_definitions("${LIB_NATIVE}-vaesf" PUBLIC BC_VAESF BC_VARIANT=\"vaesf\" BUILD_TS=\"${BUILD_TS}\")


#     #Uncomment to enable test project
#    add_executable(tryit main.c ../../debug.h)
#    target_link_libraries(tryit "${LIB_NATIVE}-vaesf")
#    target_compile_options("tryit" PRIVATE
#	            $<$<COMPILE_LANGUAGE:C>: -g -Wpsabi -mavx -msha -maes -mpclmul -mrdrnd -mrdseed -mlzcnt -mvaes -mavx2 -mvpclmulqdq -mavx512f -mavx512bw ${OPTIONS}>
#	      )


endif ()

