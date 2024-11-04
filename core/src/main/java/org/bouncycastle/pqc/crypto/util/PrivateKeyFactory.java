package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import java.io.IOException;
import java.io.InputStream;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory
{
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     *
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData)
            throws IOException
    {
        if (privateKeyInfoData == null)
        {
            throw new IllegalArgumentException("privateKeyInfoData array null");
        }
        if (privateKeyInfoData.length == 0)
        {
            throw new IllegalArgumentException("privateKeyInfoData array empty");
        }
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
     * stream.
     *
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr)
            throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     *
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        if (keyInfo == null)
        {
            throw new IllegalArgumentException("keyInfo array null");
        }

        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        if (algOID.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            ASN1BitString pubKey = keyInfo.getPublicKeyData();

            if (Pack.bigEndianToInt(keyEnc, 0) == 1)
            {
                if (pubKey != null)
                {
                    byte[] pubEnc = pubKey.getOctets();

                    return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), Arrays.copyOfRange(pubEnc, 4, pubEnc.length));
                }
                return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
            else
            {
                if (pubKey != null)
                {
                    byte[] pubEnc = pubKey.getOctets();

                    return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), pubEnc);
                }
                return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
        }
        else if (Utils.shldsaParams.containsKey(algOID))
        {
            SLHDSAParameters spParams = Utils.slhdsaParamsLookup(algOID);

            ASN1Encodable obj = keyInfo.parsePrivateKey();

            return new SLHDSAPrivateKeyParameters(spParams, ASN1OctetString.getInstance(obj).getOctets());

        }
        else if (algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_512) ||
                algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_768) ||
                algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_1024))
        {
            ASN1OctetString kyberKey = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());
            MLKEMParameters kyberParams = Utils.mlkemParamsLookup(algOID);

            return new MLKEMPrivateKeyParameters(kyberParams, kyberKey.getOctets());
        }
        else if (Utils.mldsaParams.containsKey(algOID))
        {
            ASN1Encodable keyObj = keyInfo.parsePrivateKey();
            MLDSAParameters spParams = Utils.mldsaParamsLookup(algOID);

            if (keyObj instanceof ASN1Sequence)
            {
                ASN1Sequence keyEnc = ASN1Sequence.getInstance(keyObj);

                int version = ASN1Integer.getInstance(keyEnc.getObjectAt(0)).intValueExact();
                if (version != 0)
                {
                    throw new IOException("unknown private key version: " + version);
                }

                if (keyInfo.getPublicKeyData() != null)
                {
                    MLDSAPublicKeyParameters pubParams = PublicKeyFactory.MLDSAConverter.getPublicKeyParams(spParams, keyInfo.getPublicKeyData());

                    return new MLDSAPrivateKeyParameters(spParams,
                            ASN1BitString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(4)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(5)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(6)).getOctets(),
                            pubParams.getT1()); // encT1
                }
                else
                {
                    return new MLDSAPrivateKeyParameters(spParams,
                            ASN1BitString.getInstance(keyEnc.getObjectAt(1)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(2)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(3)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(4)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(5)).getOctets(),
                            ASN1BitString.getInstance(keyEnc.getObjectAt(6)).getOctets(),
                            null);
                }
            }
            else if (keyObj instanceof DEROctetString)
            {
                byte[] data = ASN1OctetString.getInstance(keyObj).getOctets();
                if (keyInfo.getPublicKeyData() != null)
                {
                    MLDSAPublicKeyParameters pubParams = PublicKeyFactory.MLDSAConverter.getPublicKeyParams(spParams, keyInfo.getPublicKeyData());
                    return new MLDSAPrivateKeyParameters(spParams, data, pubParams);
                }
                return new MLDSAPrivateKeyParameters(spParams, data);
            }
            else
            {
                throw new IOException("not supported");
            }
        }
        else
        {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    private static short[] convert(byte[] octets)
    {
        short[] rv = new short[octets.length / 2];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Pack.littleEndianToShort(octets, i * 2);
        }

        return rv;
    }
}
