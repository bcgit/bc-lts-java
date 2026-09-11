package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class CompositeIndex
{
    private static Map<ASN1ObjectIdentifier, String[]> pairings = new HashMap<ASN1ObjectIdentifier, String[]>();
    private static Map<ASN1ObjectIdentifier, AlgorithmParameterSpec[]> kpgInitSpecs = new HashMap<ASN1ObjectIdentifier, AlgorithmParameterSpec[]>();
    private static Map<ASN1ObjectIdentifier, String> algorithmNames = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        pairings.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new String[]{"ML-DSA-44", "RSASSA-PSS"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new String[]{"ML-DSA-44", "SHA256withRSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new String[]{"ML-DSA-44", "Ed25519"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new String[]{"ML-DSA-44", "SHA256withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, new String[]{"ML-DSA-65", "RSASSA-PSS"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, new String[]{"ML-DSA-65", "SHA256withRSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512, new String[]{"ML-DSA-65", "RSASSA-PSS"});
        // id_MLDSA65_RSA4096_PKCS15_SHA512
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, new String[]{"ML-DSA-65", "SHA384withRSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, new String[]{"ML-DSA-65", "SHA256withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512, new String[]{"ML-DSA-65", "SHA384withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, new String[]{"ML-DSA-65", "SHA256withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new String[]{"ML-DSA-65", "Ed25519"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, new String[]{"ML-DSA-87", "SHA384withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, new String[]{"ML-DSA-87", "SHA384withECDSA"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, new String[]{"ML-DSA-87", "Ed448"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, new String[]{"ML-DSA-87", "RSASSA-PSS"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512, new String[]{"ML-DSA-87", "RSASSA-PSS"});
        pairings.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512, new String[]{"ML-DSA-87", "SHA512withECDSA"});

        // every component carries a spec, including the ones whose parameter set the service name
        // already fixes, because initialize(null, random) can only reach a component through one.
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_44, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_44, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_44, new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_44, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new ECNamedCurveGenParameterSpec("brainpoolP256r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_65, new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new ECNamedCurveGenParameterSpec("brainpoolP384r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new EdDSAParameterSpec(EdDSAParameterSpec.Ed448)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new ECNamedCurveGenParameterSpec("P-521")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, new AlgorithmParameterSpec[]{MLDSAParameterSpec.ml_dsa_87, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});

        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, "MLDSA44-RSA2048-PSS-SHA256");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, "MLDSA44-RSA2048-PKCS15-SHA256");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, "MLDSA44-Ed25519-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, "MLDSA44-ECDSA-P256-SHA256");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, "MLDSA65-RSA3072-PSS-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, "MLDSA65-RSA3072-PKCS15-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512, "MLDSA65-RSA4096-PSS-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, "MLDSA65-RSA4096-PKCS15-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, "MLDSA65-ECDSA-P256-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512, "MLDSA65-ECDSA-P384-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, "MLDSA65-ECDSA-brainpoolP256r1-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, "MLDSA65-Ed25519-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, "MLDSA87-ECDSA-P384-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, "MLDSA87-ECDSA-brainpoolP384r1-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, "MLDSA87-Ed448-SHAKE256");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512, "MLDSA87-RSA4096-PSS-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512, "MLDSA87-ECDSA-P521-SHA512");
        algorithmNames.put(IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, "MLDSA87-RSA3072-PSS-SHA512");
    }

    public static boolean isAlgorithmSupported(ASN1ObjectIdentifier algorithm)
    {
        return pairings.containsKey(algorithm);
    }

    public static Set<ASN1ObjectIdentifier> getSupportedIdentifiers()
    {
        return pairings.keySet();
    }

    public static String getAlgorithmName(ASN1ObjectIdentifier algorithm)
    {
        return algorithmNames.get(algorithm);
    }

    static String[] getPairing(ASN1ObjectIdentifier algorithm)
    {
        return pairings.get(algorithm);
    }

    static AlgorithmParameterSpec[] getKeyPairSpecs(ASN1ObjectIdentifier algorithm)
    {
        return kpgInitSpecs.get(algorithm);
    }

    static Digest getDigest(ASN1ObjectIdentifier algOid)
    {
        String algName = algorithmNames.get(algOid);

        if (algName.endsWith("SHA256"))
        {
            return new SHA256Digest();
        }

        if (algName.endsWith("SHA384"))
        {
            return new SHA384Digest();
        }

        if (algName.endsWith("SHA512"))
        {
            return new SHA512Digest();
        }

        return new SHAKEDigest(256);
    }

    static String getBaseName(String name)
    {
        if (name.indexOf("RSA") >= 0)
        {
            return "RSA";
        }
        if (name.indexOf("ECDSA") >= 0)
        {
            return "EC";
        }

        return name;
    }
}
