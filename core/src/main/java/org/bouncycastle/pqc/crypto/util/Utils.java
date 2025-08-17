package org.bouncycastle.pqc.crypto.util;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;


class Utils
{
    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);

    static final AlgorithmIdentifier XMSS_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    static final AlgorithmIdentifier XMSS_SHA512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
    static final AlgorithmIdentifier XMSS_SHAKE128 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
    static final AlgorithmIdentifier XMSS_SHAKE256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);

    static final Map categories = new HashMap();

//    static final Map picnicOids = new HashMap();
//    static final Map picnicParams = new HashMap();
//
//    static final Map frodoOids = new HashMap();
//    static final Map frodoParams = new HashMap();
//
//    static final Map saberOids = new HashMap();
//    static final Map saberParams = new HashMap();
//
//    static final Map mcElieceOids = new HashMap();
//    static final Map mcElieceParams = new HashMap();
//
//    static final Map sphincsPlusOids = new HashMap();
//    static final Map sphincsPlusParams = new HashMap();

//    static final Map sikeOids = new HashMap();
//    static final Map sikeParams = new HashMap();
//
//    static final Map ntruOids = new HashMap();
//    static final Map ntruParams = new HashMap();
//
//    static final Map falconOids = new HashMap();
//    static final Map falconParams = new HashMap();
//
//    static final Map ntruprimeOids = new HashMap();
//    static final Map ntruprimeParams = new HashMap();
//
//    static final Map sntruprimeOids = new HashMap();
//    static final Map sntruprimeParams = new HashMap();
//
//    static final Map dilithiumOids = new HashMap();
//    static final Map dilithiumParams = new HashMap();
//
//    static final Map bikeOids = new HashMap();
//    static final Map bikeParams = new HashMap();
//
//    static final Map hqcOids = new HashMap();
//    static final Map hqcParams = new HashMap();
//
//    static final Map rainbowOids = new HashMap();
//    static final Map rainbowParams = new HashMap();

    static final Map mlkemOids = new HashMap<ASN1ObjectIdentifier, MLKEMParameters>();
    static final Map mlkemParams = new HashMap<MLKEMParameters, ASN1ObjectIdentifier>();

    static final Map mldsaOids = new HashMap<ASN1ObjectIdentifier, MLDSAParameters>();
    static final Map mldsaParams = new HashMap<MLDSAParameters, ASN1ObjectIdentifier>();

    static final Map slhdsaOids = new HashMap<ASN1ObjectIdentifier, SLHDSAParameters>();
    static final Map slhdsaParams = new HashMap<SLHDSAParameters, ASN1ObjectIdentifier>();

    static
    {
        mlkemOids.put(MLKEMParameters.ml_kem_512, NISTObjectIdentifiers.id_alg_ml_kem_512);
        mlkemOids.put(MLKEMParameters.ml_kem_768, NISTObjectIdentifiers.id_alg_ml_kem_768);
        mlkemOids.put(MLKEMParameters.ml_kem_1024, NISTObjectIdentifiers.id_alg_ml_kem_1024);

        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_512, MLKEMParameters.ml_kem_512);
        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_768, MLKEMParameters.ml_kem_768);
        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_1024, MLKEMParameters.ml_kem_1024);


        mldsaOids.put(MLDSAParameters.ml_dsa_44, NISTObjectIdentifiers.id_ml_dsa_44);
        mldsaOids.put(MLDSAParameters.ml_dsa_65, NISTObjectIdentifiers.id_ml_dsa_65);
        mldsaOids.put(MLDSAParameters.ml_dsa_87, NISTObjectIdentifiers.id_ml_dsa_87);
        mldsaOids.put(MLDSAParameters.ml_dsa_44_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        mldsaOids.put(MLDSAParameters.ml_dsa_65_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        mldsaOids.put(MLDSAParameters.ml_dsa_87_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);

        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_44, MLDSAParameters.ml_dsa_44);
        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_65, MLDSAParameters.ml_dsa_65);
        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_87, MLDSAParameters.ml_dsa_87);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, MLDSAParameters.ml_dsa_44_with_sha512);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, MLDSAParameters.ml_dsa_65_with_sha512);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, MLDSAParameters.ml_dsa_87_with_sha512);


        slhdsaOids.put(SLHDSAParameters.sha2_128s, NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        slhdsaOids.put(SLHDSAParameters.sha2_128f, NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        slhdsaOids.put(SLHDSAParameters.sha2_192s, NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        slhdsaOids.put(SLHDSAParameters.sha2_192f, NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        slhdsaOids.put(SLHDSAParameters.sha2_256s, NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        slhdsaOids.put(SLHDSAParameters.sha2_256f, NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        slhdsaOids.put(SLHDSAParameters.shake_128s, NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        slhdsaOids.put(SLHDSAParameters.shake_128f, NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        slhdsaOids.put(SLHDSAParameters.shake_192s, NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        slhdsaOids.put(SLHDSAParameters.shake_192f, NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        slhdsaOids.put(SLHDSAParameters.shake_256s, NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        slhdsaOids.put(SLHDSAParameters.shake_256f, NISTObjectIdentifiers.id_slh_dsa_shake_256f);

        slhdsaOids.put(SLHDSAParameters.sha2_128s_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        slhdsaOids.put(SLHDSAParameters.sha2_128f_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        slhdsaOids.put(SLHDSAParameters.sha2_192s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_192f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_256s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_256f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        slhdsaOids.put(SLHDSAParameters.shake_128s_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        slhdsaOids.put(SLHDSAParameters.shake_128f_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        slhdsaOids.put(SLHDSAParameters.shake_192s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_192f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_256s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_256f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);

        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, SLHDSAParameters.sha2_128s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, SLHDSAParameters.sha2_128f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, SLHDSAParameters.sha2_192s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, SLHDSAParameters.sha2_192f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, SLHDSAParameters.sha2_256s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, SLHDSAParameters.sha2_256f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s, SLHDSAParameters.shake_128s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f, SLHDSAParameters.shake_128f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s, SLHDSAParameters.shake_192s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f, SLHDSAParameters.shake_192f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s, SLHDSAParameters.shake_256s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f, SLHDSAParameters.shake_256f);

        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, SLHDSAParameters.sha2_128s_with_sha256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, SLHDSAParameters.sha2_128f_with_sha256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, SLHDSAParameters.sha2_192s_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, SLHDSAParameters.sha2_192f_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, SLHDSAParameters.sha2_256s_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, SLHDSAParameters.sha2_256f_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, SLHDSAParameters.shake_128s_with_shake128);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, SLHDSAParameters.shake_128f_with_shake128);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, SLHDSAParameters.shake_192s_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, SLHDSAParameters.shake_192f_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, SLHDSAParameters.shake_256s_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, SLHDSAParameters.shake_256f_with_shake256);

//        sphincsPlusOids.put(SLHDSAParameters.sha2_128s, BCObjectIdentifiers.sphincsPlus_sha2_128s);
//        sphincsPlusOids.put(SLHDSAParameters.sha2_128f, BCObjectIdentifiers.sphincsPlus_sha2_128f);
//        sphincsPlusOids.put(SLHDSAParameters.sha2_192s, BCObjectIdentifiers.sphincsPlus_sha2_192s);
//        sphincsPlusOids.put(SLHDSAParameters.sha2_192f, BCObjectIdentifiers.sphincsPlus_sha2_192f);
//        sphincsPlusOids.put(SLHDSAParameters.sha2_256s, BCObjectIdentifiers.sphincsPlus_sha2_256s);
//        sphincsPlusOids.put(SLHDSAParameters.sha2_256f, BCObjectIdentifiers.sphincsPlus_sha2_256f);
//        sphincsPlusOids.put(SLHDSAParameters.shake_128s, BCObjectIdentifiers.sphincsPlus_shake_128s);
//        sphincsPlusOids.put(SLHDSAParameters.shake_128f, BCObjectIdentifiers.sphincsPlus_shake_128f);
//        sphincsPlusOids.put(SLHDSAParameters.shake_192s, BCObjectIdentifiers.sphincsPlus_shake_192s);
//        sphincsPlusOids.put(SLHDSAParameters.shake_192f, BCObjectIdentifiers.sphincsPlus_shake_192f);
//        sphincsPlusOids.put(SLHDSAParameters.shake_256s, BCObjectIdentifiers.sphincsPlus_shake_256s);
//        sphincsPlusOids.put(SLHDSAParameters.shake_256f, BCObjectIdentifiers.sphincsPlus_shake_256f);
    }

    static ASN1ObjectIdentifier slhdsaOidLookup(SLHDSAParameters params)
    {
        return (ASN1ObjectIdentifier)slhdsaOids.get(params);
    }

    static SLHDSAParameters slhdsaParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SLHDSAParameters)slhdsaParams.get(oid);
    }

    static int qTeslaLookupSecurityCategory(AlgorithmIdentifier algorithm)
    {
        return ((Integer)categories.get(algorithm.getAlgorithm())).intValue();
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    public static AlgorithmIdentifier getAlgorithmIdentifier(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        }
        if (digestName.equals("SHA-224"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224);
        }
        if (digestName.equals("SHA-256"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (digestName.equals("SHA-384"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        if (digestName.equals("SHA-512"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }

    public static String getDigestName(ASN1ObjectIdentifier digestOid)
    {
        if (digestOid.equals(OIWObjectIdentifiers.idSHA1))
        {
            return "SHA-1";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha224))
        {
            return "SHA-224";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return "SHA-256";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha384))
        {
            return "SHA-384";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return "SHA-512";
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestOid);
    }

    static ASN1ObjectIdentifier mlkemOidLookup(MLKEMParameters params)
    {
        return (ASN1ObjectIdentifier)mlkemOids.get(params);
    }

    static MLKEMParameters mlkemParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (MLKEMParameters)mlkemParams.get(oid);
    }


    static ASN1ObjectIdentifier mldsaOidLookup(MLDSAParameters params)
    {
        return (ASN1ObjectIdentifier)mldsaOids.get(params);
    }

    static MLDSAParameters mldsaParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (MLDSAParameters)mldsaParams.get(oid);
    }

    private static boolean isRaw(byte[] data)
    {
        // check well-formed first
        ByteArrayInputStream bIn = new ByteArrayInputStream(data);

        int tag = bIn.read();
        int len = readLen(bIn);
        if (len != bIn.available())
        {
            return true;
        }

        return false;
    }

    static ASN1OctetString parseOctetData(byte[] data)
    {
        // check well-formed first
        if (!isRaw(data))
        {
            if (data[0] == BERTags.OCTET_STRING)
            {
                return ASN1OctetString.getInstance(data);
            }
        }

        return null;
    }

    static ASN1Primitive parseData(byte[] data)
    {
        // check well-formed first
        if (!isRaw(data))
        {
            if (data[0] == (BERTags.SEQUENCE | BERTags.CONSTRUCTED))
            {
                return ASN1Sequence.getInstance(data);
            }

            if (data[0] == BERTags.OCTET_STRING)
            {
                return ASN1OctetString.getInstance(data);
            }

            if ((data[0] & 0xff) == BERTags.TAGGED)
            {
                return ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(data), false);
            }
        }

        return null;
    }

    /**
     * ASN.1 length reader.
     */
    static int readLen(ByteArrayInputStream bIn)
    {
        int length = bIn.read();
        if (length < 0)
        {
            return -1;
        }
        if (length != (length & 0x7f))
        {
            int count = length & 0x7f;
            length = 0;
            while (count-- != 0)
            {
                length = (length << 8) + bIn.read();
            }
        }

        return length;
    }
}
