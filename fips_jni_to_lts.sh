#!/bin/sh
#
# Update JNI method names to reflect the LTS library names

for i in native_c/jni/*.c
do

    ed $i <<%%%
/Java_org_bouncycastle_crypto_fips_AESNativeEngine/s//Java_org_bouncycastle_crypto_engines_AESNativeEngine/g
/Java_org_bouncycastle_crypto_fips_AESNativeCBC/s//Java_org_bouncycastle_crypto_engines_AESNativeCBC/g
/Java_org_bouncycastle_crypto_fips_AESNativeCFB/s//Java_org_bouncycastle_crypto_engines_AESNativeCFB/g
/Java_org_bouncycastle_crypto_fips_AESNativeCTR/s//Java_org_bouncycastle_crypto_engines_AESNativeCTR/g
/Java_org_bouncycastle_crypto_fips_AESNativeGCM/s//Java_org_bouncycastle_crypto_engines_AESNativeGCM/g
/Java_org_bouncycastle_crypto_fips_SHA256NativeDigest/s//Java_org_bouncycastle_crypto_digests_SHA256NativeDigest/g
w
q
%%%

done
