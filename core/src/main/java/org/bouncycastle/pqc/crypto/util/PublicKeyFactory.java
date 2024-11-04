package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory to create asymmetric public key parameters for asymmetric ciphers from range of
 * ASN.1 encoded SubjectPublicKeyInfo objects.
 */
public class PublicKeyFactory
{
    private static Map converters = new HashMap();

    static
    {

        converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter());


        converters.put(NISTObjectIdentifiers.id_alg_ml_kem_512, new MLKEMConverter());
        converters.put(NISTObjectIdentifiers.id_alg_ml_kem_768, new MLKEMConverter());
        converters.put(NISTObjectIdentifiers.id_alg_ml_kem_1024, new MLKEMConverter());

        converters.put(NISTObjectIdentifiers.id_ml_dsa_44, new MLDSAConverter());
        converters.put(NISTObjectIdentifiers.id_ml_dsa_65, new MLDSAConverter());
        converters.put(NISTObjectIdentifiers.id_ml_dsa_87, new MLDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, new MLDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, new MLDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, new MLDSAConverter());


        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, new SLHDSAConverter());
        converters.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, new SLHDSAConverter());
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding
     *
     * @param keyInfoData the SubjectPublicKeyInfo encoding
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] keyInfoData)
        throws IOException
    {
        if (keyInfoData == null)
        {
            throw new IllegalArgumentException("keyInfoData array null");
        }
        if (keyInfoData.length == 0)
        {
            throw new IllegalArgumentException("keyInfoData array empty");
        }
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding read from a stream
     *
     * @param inStr the stream to read the SubjectPublicKeyInfo encoding from
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr)
        throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo the SubjectPublicKeyInfo containing the key data
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        if (keyInfo == null)
        {
            throw new IllegalArgumentException("keyInfo argument null");
        }
        return createKey(keyInfo, null);
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     *
     * @param keyInfo       the SubjectPublicKeyInfo containing the key data
     * @param defaultParams default parameters that might be needed.
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        throws IOException
    {
        if (keyInfo == null)
        {
            throw new IllegalArgumentException("keyInfo argument null");
        }

        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter)converters.get(algId.getAlgorithm());

        if (converter != null)
        {
            return converter.getPublicKeyParameters(keyInfo, defaultParams);
        }
        else
        {
            throw new IOException("algorithm identifier in public key not recognised: " + algId.getAlgorithm());
        }
    }

    private static abstract class SubjectPublicKeyInfoConverter
    {
        abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException;
    }

    private static class LMSConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();

            if (Pack.bigEndianToInt(keyEnc, 0) == 1)
            {
                return LMSPublicKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            else
            {
                // public key with extra tree height
                if (keyEnc.length == 64)
                {
                    keyEnc = Arrays.copyOfRange(keyEnc, 4, keyEnc.length);
                }
                return HSSPublicKeyParameters.getInstance(keyEnc);
            }
        }
    }

    static class MLDSAConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            MLDSAParameters dilithiumParams = Utils.mldsaParamsLookup(keyInfo.getAlgorithm().getAlgorithm());

            return getPublicKeyParams(dilithiumParams, keyInfo.getPublicKeyData());
        }

        static MLDSAPublicKeyParameters getPublicKeyParams(MLDSAParameters dilithiumParams, ASN1BitString publicKeyData)
        {
            try
            {
                ASN1Primitive obj = ASN1Primitive.fromByteArray(publicKeyData.getOctets());
                if (obj instanceof ASN1Sequence)
                {
                    ASN1Sequence keySeq = ASN1Sequence.getInstance(obj);

                    return new MLDSAPublicKeyParameters(dilithiumParams,
                        ASN1OctetString.getInstance(keySeq.getObjectAt(0)).getOctets(),
                        ASN1OctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
                }
                else
                {
                    byte[] encKey = ASN1OctetString.getInstance(obj).getOctets();

                    return new MLDSAPublicKeyParameters(dilithiumParams, encKey);
                }
            }
            catch (Exception e)
            {
                // we're a raw encoding
                return new MLDSAPublicKeyParameters(dilithiumParams, publicKeyData.getOctets());
            }
        }
    }


    private static class SLHDSAConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            try
            {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();

                SLHDSAParameters spParams = Utils.slhdsaParamsLookup(keyInfo.getAlgorithm().getAlgorithm());

                return new SLHDSAPublicKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            catch (Exception e)
            {
                byte[] keyEnc = keyInfo.getPublicKeyData().getOctets();

                SLHDSAParameters spParams = Utils.slhdsaParamsLookup(keyInfo.getAlgorithm().getAlgorithm());

                return new SLHDSAPublicKeyParameters(spParams, keyEnc);
            }
        }
    }

    private static class MLKEMConverter
        extends SubjectPublicKeyInfoConverter
    {
        AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
            throws IOException
        {
            MLKEMParameters mlkemParameters = Utils.mlkemParamsLookup(keyInfo.getAlgorithm().getAlgorithm());

            return new MLKEMPublicKeyParameters(mlkemParameters, keyInfo.getPublicKeyData().getOctets());
        }
    }
}
