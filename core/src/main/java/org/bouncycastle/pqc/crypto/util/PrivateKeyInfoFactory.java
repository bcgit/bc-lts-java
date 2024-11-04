package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;

import java.io.IOException;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{
    private PrivateKeyInfoFactory()
    {
    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException
    {
        if (privateKey instanceof LMSPrivateKeyParameters)
        {
            LMSPrivateKeyParameters params = (LMSPrivateKeyParameters) privateKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(1).bytes(params.getPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        else if (privateKey instanceof HSSPrivateKeyParameters)
        {
            HSSPrivateKeyParameters params = (HSSPrivateKeyParameters) privateKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(params.getL()).bytes(params.getPublicKey().getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }

        else if (privateKey instanceof SLHDSAPrivateKeyParameters)
        {
            SLHDSAPrivateKeyParameters params = (SLHDSAPrivateKeyParameters) privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, params.getPublicKey());
        }
        else if (privateKey instanceof MLKEMPrivateKeyParameters)
        {
            MLKEMPrivateKeyParameters params = (MLKEMPrivateKeyParameters) privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

            byte[] seed = params.getSeed();
            if (seed == null)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
            }
            else
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(seed), attributes);
            }
        }
        else if (privateKey instanceof MLDSAPrivateKeyParameters)
        {
            MLDSAPrivateKeyParameters params = (MLDSAPrivateKeyParameters) privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

            byte[] seed = params.getSeed();
            if (seed == null)
            {
                MLDSAPublicKeyParameters pubParams = params.getPublicKeyParameters();

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, pubParams.getEncoded());
            }
            else
            {
                MLDSAPublicKeyParameters pubParams = params.getPublicKeyParameters();

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getSeed()), attributes);
            }
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

}
