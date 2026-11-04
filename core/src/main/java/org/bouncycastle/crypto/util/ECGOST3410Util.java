package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;

/**
 * Shared logic for encoding ECGOST3410 keys, used by {@link SubjectPublicKeyInfoFactory} and
 * {@link PrivateKeyInfoFactory} so that the two stay in step.
 */
// TODO[ecgost] The JCE provider does not use this: the four key classes under
// org.bouncycastle.jcajce.provider.asymmetric.ecgost and .ecgost12 each carry their own encoder (taking the
// algorithm OID from the class and 256/512 from a bitLength() heuristic) and their own decoder. The
// consolidation notes on those classes point at delegating to the two factories here, so this class stays
// package-private for now; it need only become public if the provider ends up calling the rule directly.
class ECGOST3410Util
{
    /**
     * Create the key AlgorithmIdentifier under which an ECGOST3410 key should be encoded (in a
     * SubjectPublicKeyInfo or a PrivateKeyInfo).
     * <p>
     * GOST R 34.10-2001 keys (RFC 4491, Section 2.3.2) carry a GOST R 34.11-94 digestParamSet, whereas
     * GOST R 34.10-2012 keys (RFC 9215, Section 4.2) carry a GOST R 34.11-2012 digestParamSet or omit it.
     * RFC 9215 also permits the legacy GOST R 34.10-2001 parameter sets to be used as the
     * publicKeyParamSet of a GOST R 34.10-2012 key, so the digest parameter set (not the curve) is the
     * discriminator between 2001 and 2012.
     *
     * @throws IllegalArgumentException if the digest parameter set is not recognised.
     */
    static AlgorithmIdentifier createAlgorithmIdentifier(ECGOST3410Parameters parameters)
    {
        ASN1ObjectIdentifier algOid = getKeyAlgorithmOid(parameters);
        GOST3410PublicKeyAlgParameters algParams = new GOST3410PublicKeyAlgParameters(
            parameters.getPublicKeyParamSet(), parameters.getDigestParamSet(), parameters.getEncryptionParamSet());

        return new AlgorithmIdentifier(algOid, algParams);
    }

    /**
     * Determine the key algorithm OID (GOST R 34.10-2001, or GOST R 34.10-2012 with 256- or 512-bit
     * keys) for an ECGOST3410 key. See {@link #createAlgorithmIdentifier(ECGOST3410Parameters)} for
     * the rules.
     *
     * @throws IllegalArgumentException if the digest parameter set is not recognised.
     */
    static ASN1ObjectIdentifier getKeyAlgorithmOid(ECGOST3410Parameters parameters)
    {
        ASN1ObjectIdentifier digestParamSet = parameters.getDigestParamSet();

        if (digestParamSet == null
            || RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.equals(digestParamSet)
            || RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.equals(digestParamSet))
        {
            return getFieldElementEncodingLength(parameters) > 32
                ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512
                : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
        }

        if (CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet.equals(digestParamSet)
            || CryptoProObjectIdentifiers.gostR3411_94_TestParamSet.equals(digestParamSet))
        {
            return CryptoProObjectIdentifiers.gostR3410_2001;
        }

        throw new IllegalArgumentException("unrecognised GOST R 34.11 digestParamSet: " + digestParamSet);
    }

    /**
     * The size in octets of a field element (and so of each coordinate and of the private key) for the
     * key's curve: 32 for the 256-bit parameter sets, 64 for the 512-bit ones.
     */
    static int getFieldElementEncodingLength(ECGOST3410Parameters parameters)
    {
        return parameters.getCurve().getFieldElementEncodingLength();
    }
}
