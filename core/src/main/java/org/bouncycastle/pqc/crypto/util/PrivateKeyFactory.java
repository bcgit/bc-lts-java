package org.bouncycastle.pqc.crypto.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
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
            ASN1OctetString slhdsaKey = parseOctetString(keyInfo.getPrivateKey());
            SLHDSAParameters spParams = Utils.slhdsaParamsLookup(algOID);

            return new SLHDSAPrivateKeyParameters(spParams, slhdsaKey.getOctets());
        }
        else if (algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_512) ||
                algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_768) ||
                algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_1024))
        {
            ASN1OctetString mlkemKey = parseOctetString(keyInfo.getPrivateKey());
            MLKEMParameters mlkemParams = Utils.mlkemParamsLookup(algOID);

            return new MLKEMPrivateKeyParameters(mlkemParams, mlkemKey.getOctets());
        }
        else if (Utils.mldsaParams.containsKey(algOID))
        {
            ASN1Encodable keyObj = parseOctetString(keyInfo.getPrivateKey());
            MLDSAParameters spParams = Utils.mldsaParamsLookup(algOID);

            if (keyObj instanceof DEROctetString)
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

    /**
     * So it seems for the new PQC algorithms, there's a couple of approaches to what goes in the OCTET STRING
     */
    private static ASN1OctetString parseOctetString(ASN1OctetString octStr)
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(octStr.getOctets());

        int tag = bIn.read();
        int len = readLen(bIn);
        if (tag == BERTags.OCTET_STRING)
        {
            if (len == bIn.available())
            {
                return ASN1OctetString.getInstance(octStr.getOctets());
            }
        }
        if (tag == BERTags.CONTEXT_SPECIFIC)
        {
            if (len == bIn.available())
            {
                return ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(octStr.getOctets()), false);
            }
        }
        if (tag == (BERTags.CONTEXT_SPECIFIC | BERTags.CONSTRUCTED))
        {
            if (len == bIn.available())
            {
                return ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(octStr.getOctets()), true);
            }
        }

        return octStr;
    }

    private static int readLen(ByteArrayInputStream bIn)
    {
        int length = bIn.read();
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
