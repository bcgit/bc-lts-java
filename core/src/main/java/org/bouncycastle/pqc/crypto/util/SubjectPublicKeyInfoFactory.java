package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;


import java.io.IOException;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
            throws IOException
    {

        if (publicKey instanceof LMSPublicKeyParameters)
        {
            LMSPublicKeyParameters params = (LMSPublicKeyParameters) publicKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof HSSPublicKeyParameters)
        {
            HSSPublicKeyParameters params = (HSSPublicKeyParameters) publicKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params.getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof SLHDSAPublicKeyParameters)
        {
            SLHDSAPublicKeyParameters params = (SLHDSAPublicKeyParameters) publicKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));
            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        else if (publicKey instanceof MLKEMPublicKeyParameters)
        {
            MLKEMPublicKeyParameters params = (MLKEMPublicKeyParameters) publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else if (publicKey instanceof MLDSAPublicKeyParameters)
        {
            MLDSAPublicKeyParameters params = (MLDSAPublicKeyParameters) publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getEncoded());
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
