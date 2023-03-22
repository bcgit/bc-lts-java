#!/bin/sh
#
# Update JNI method names to reflect the LTS library names

for i in native_c/intel/jni/*.c
do
    ed $i <<%%%
g/org_bouncycastle_crypto_fips_AESNativeEngine/s//org_bouncycastle_crypto_engines_AESNativeEngine/g
g/org_bouncycastle_crypto_fips_AESNativeCBC/s//org_bouncycastle_crypto_engines_AESNativeCBC/g
g/org_bouncycastle_crypto_fips_AESNativeCFB/s//org_bouncycastle_crypto_engines_AESNativeCFB/g
g/org_bouncycastle_crypto_fips_AESNativeCTR/s//org_bouncycastle_crypto_engines_AESNativeCTR/g
g/org_bouncycastle_crypto_fips_AESNativeGCM/s//org_bouncycastle_crypto_engines_AESNativeGCM/g
g/org_bouncycastle_crypto_fips_SHA256NativeDigest/s//org_bouncycastle_crypto_digests_SHA256NativeDigest/g
g/org_bouncycastle_crypto_fips_NativeEntropySource/s//org_bouncycastle_crypto_NativeEntropySource/g
g/org_bouncycastle_crypto_fips_VariantSelector/s//org_bouncycastle_crypto_VariantSelector/g
g/org_bouncycastle_crypto_fips_NativeLibIdentity/s//org_bouncycastle_crypto_NativeLibIdentity/g
g/org_bouncycastle_crypto_fips_NativeFeatures/s//org_bouncycastle_crypto_NativeFeatures/g
g/org_bouncycastle_crypto_fips_Probe/s//org_bouncycastle_crypto_Probe/g
w
q
%%%

done

