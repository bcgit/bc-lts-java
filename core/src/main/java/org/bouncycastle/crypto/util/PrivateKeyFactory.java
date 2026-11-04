package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.ElGamalParameter;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.util.Arrays;

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
            throw new IllegalArgumentException("keyInfo argument null");
        }

        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        if (algOID.equals(PKCSObjectIdentifiers.rsaEncryption)
            || algOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
            || algOID.equals(X509ObjectIdentifiers.id_ea_rsa))
        {
            RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

            return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(),
                keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(),
                keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(),
                keyStructure.getExponent2(), keyStructure.getCoefficient());
        }
        // TODO?
//      else if (algOID.equals(X9ObjectIdentifiers.dhpublicnumber))
        else if (algOID.equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter params = DHParameter.getInstance(requiredParameters(algId, "DH"));
            ASN1Integer derX = ASN1Integer.getInstance(keyInfo.parsePrivateKey());

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPrivateKeyParameters(derX.getValue(), dhParams);
        }
        else if (algOID.equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter params = ElGamalParameter.getInstance(requiredParameters(algId, "ElGamal"));
            ASN1Integer derX = ASN1Integer.getInstance(keyInfo.parsePrivateKey());

            return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(
                params.getP(), params.getG()));
        }
        else if (algOID.equals(X9ObjectIdentifiers.id_dsa))
        {
            ASN1Integer derX = ASN1Integer.getInstance(keyInfo.parsePrivateKey());
            ASN1Encodable algParameters = algId.getParameters();

            DSAParameters parameters = null;
            if (algParameters != null)
            {
                DSAParameter params = DSAParameter.getInstance(algParameters.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPrivateKeyParameters(derX.getValue(), parameters);
        }
        /*
         * TODO id-ecDH (SECObjectIdentifiers.ecdh) and/or id-ecMQV (SECObjectIdentifiers.ecmqv) could be supported if
         * we could properly restrict usage of the resulting key.
         */
        else if (algOID.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            /*
             * TODO Consistency checks in case parameters and/or public key are specified at both the
             * PrivateKeyInfo and ECPrivateKey levels?
             */
            ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(keyInfo.parsePrivateKey());

            // RFC 5480 puts the curve in the algorithm parameters; RFC 5915 also allows it in the
            // ECPrivateKey, which is used when the algorithm carries none
            ASN1Encodable curve = algId.getParameters();
            if (curve == null)
            {
                curve = ecPrivateKey.getParametersObject();
            }
            if (curve == null)
            {
                throw new IllegalArgumentException("EC private key requires curve parameters");
            }
            X962Parameters parameters = X962Parameters.getInstance(curve.toASN1Primitive());
            ECDomainParameters domainParams;
            if (parameters.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(parameters.getParameters());
                domainParams = ECNamedDomainParameters.lookup(oid);
            }
            else
            {
                X9ECParameters x9 = X9ECParameters.getInstance(parameters.getParameters());
                domainParams = new ECDomainParameters(x9);
            }

            BigInteger d = ecPrivateKey.getKey();

            return new ECPrivateKeyParameters(d, domainParams);
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_X25519))
        {
            // Java 11 bug: exact length of X25519/X448 secret used in Java 11
            if (X25519PrivateKeyParameters.KEY_SIZE == keyInfo.getPrivateKeyLength())
            {
                return new X25519PrivateKeyParameters(keyInfo.getPrivateKey().getOctets());
            }

            return new X25519PrivateKeyParameters(getRawKey(keyInfo));
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_X448))
        {
            // Java 11 bug: exact length of X25519/X448 secret used in Java 11
            if (X448PrivateKeyParameters.KEY_SIZE == keyInfo.getPrivateKeyLength())
            {
                return new X448PrivateKeyParameters(keyInfo.getPrivateKey().getOctets());
            }

            return new X448PrivateKeyParameters(getRawKey(keyInfo));
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return new Ed25519PrivateKeyParameters(getRawKey(keyInfo));
        }
        else if (algOID.equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new Ed448PrivateKeyParameters(getRawKey(keyInfo));
        }
        else if (Utils.mldsaParams.containsKey(algOID))
        {
            MLDSAParameters mldsaParams = Utils.mldsaParamsLookup(algOID);
            ASN1Primitive mldsaKey = parsePrivateKeyChoice(keyInfo.getPrivateKey(), 32, mldsaExpandedKeyLength(mldsaParams), mldsaParams.getName());

            MLDSAPublicKeyParameters pubParams = null;
            if (keyInfo.getPublicKeyData() != null)
            {
                pubParams = PublicKeyFactory.MLDSAConverter.getPublicKeyParams(mldsaParams, keyInfo.getPublicKeyData());
            }

            if (mldsaKey instanceof ASN1TaggedObject)
            {
                // RFC 9881 sec. 6: seed [0] OCTET STRING (SIZE (32))
                byte[] seed = ASN1OctetString.getInstance((ASN1TaggedObject)mldsaKey, false).getOctets();
                checkChoiceLength(seed, 32, mldsaParams.getName(), "seed");

                return new MLDSAPrivateKeyParameters(mldsaParams, seed, pubParams);
            }
            else if (mldsaKey instanceof ASN1OctetString)
            {
                // RFC 9881 sec. 6: expandedKey OCTET STRING (SIZE (2560 | 4032 | 4896)); the constructor rejects any
                // other length but the 32 bytes of a seed, which parsePrivateKeyChoice only lets through for the
                // pre-RFC forms of the seed
                return new MLDSAPrivateKeyParameters(mldsaParams, ((ASN1OctetString)mldsaKey).getOctets(), pubParams);
            }
            else if (mldsaKey instanceof ASN1Sequence)
            {
                // RFC 9881 sec. 6: both SEQUENCE { seed OCTET STRING (SIZE (32)), expandedKey OCTET STRING (SIZE (n)) }
                ASN1Sequence keySeq = (ASN1Sequence)mldsaKey;
                if (keySeq.size() != 2)
                {
                    throw new IllegalArgumentException("invalid " + mldsaParams.getName() + " private key: both must have 2 elements");
                }
                byte[] seed = ASN1OctetString.getInstance(keySeq.getObjectAt(0)).getOctets();
                byte[] encoding = ASN1OctetString.getInstance(keySeq.getObjectAt(1)).getOctets();
                checkChoiceLength(seed, 32, mldsaParams.getName(), "seed");

                MLDSAPrivateKeyParameters mldsaPriv = new MLDSAPrivateKeyParameters(mldsaParams, seed, pubParams);

                /*
                 * RFC 9881 8.2. When receiving a private key that contains both the seed and the expandedKey, the
                 * recipient SHOULD perform a seed consistency check [..] If the check is done and the seed and the
                 * expandedKey are not consistent, the recipient MUST reject the private key as malformed.
                 */
                byte[] expanded = mldsaPriv.getEncoded();
                checkChoiceLength(encoding, expanded.length, mldsaParams.getName(), "expandedKey");
                if (!Arrays.constantTimeAreEqual(expanded, encoding))
                {
                    throw new IllegalArgumentException("inconsistent " + mldsaParams.getName() + " private key");
                }

                return mldsaPriv;
            }

            throw new IllegalArgumentException("invalid " + mldsaParams.getName() + " private key");
        }
        else if (algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_512) ||
            algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_768) ||
            algOID.equals(NISTObjectIdentifiers.id_alg_ml_kem_1024))
        {
            MLKEMParameters mlkemParams = Utils.mlkemParamsLookup(algOID);
            ASN1Primitive mlkemKey = parsePrivateKeyChoice(keyInfo.getPrivateKey(), 64, mlkemExpandedKeyLength(mlkemParams), mlkemParams.getName());

            MLKEMPublicKeyParameters pubParams = null;
            if (keyInfo.getPublicKeyData() != null)
            {
                pubParams = PublicKeyFactory.MLKEMConverter.getPublicKeyParams(mlkemParams, keyInfo.getPublicKeyData());
            }

            if (mlkemKey instanceof ASN1TaggedObject)
            {
                // RFC 9935 sec. 6: seed [0] OCTET STRING (SIZE (64))
                byte[] seed = ASN1OctetString.getInstance((ASN1TaggedObject)mlkemKey, false).getOctets();
                checkChoiceLength(seed, 64, mlkemParams.getName(), "seed");

                return new MLKEMPrivateKeyParameters(mlkemParams, seed, pubParams);
            }
            else if (mlkemKey instanceof ASN1OctetString)
            {
                // RFC 9935 sec. 6: expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)); the constructor rejects any
                // other length but the 64 bytes of a seed, which parsePrivateKeyChoice only lets through for the
                // pre-RFC forms of the seed
                return new MLKEMPrivateKeyParameters(mlkemParams, ((ASN1OctetString)mlkemKey).getOctets(), pubParams);
            }
            else if (mlkemKey instanceof ASN1Sequence)
            {
                // RFC 9935 sec. 6: both SEQUENCE { seed OCTET STRING (SIZE (64)), expandedKey OCTET STRING (SIZE (n)) }
                ASN1Sequence keySeq = (ASN1Sequence)mlkemKey;
                if (keySeq.size() != 2)
                {
                    throw new IllegalArgumentException("invalid " + mlkemParams.getName() + " private key: both must have 2 elements");
                }
                byte[] seed = ASN1OctetString.getInstance(keySeq.getObjectAt(0)).getOctets();
                byte[] encoding = ASN1OctetString.getInstance(keySeq.getObjectAt(1)).getOctets();
                checkChoiceLength(seed, 64, mlkemParams.getName(), "seed");

                MLKEMPrivateKeyParameters mlkemPriv = new MLKEMPrivateKeyParameters(mlkemParams, seed, pubParams);

                /*
                 * RFC 9881 8.2. When receiving a private key that contains both the seed and the expandedKey, the
                 * recipient SHOULD perform a seed consistency check to ensure that the sender properly generated
                 * the private key. [..] If the check is done and the seed and the expandedKey are not consistent,
                 * the recipient MUST reject the private key as malformed.
                 */
                byte[] expanded = mlkemPriv.getEncoded();
                checkChoiceLength(encoding, expanded.length, mlkemParams.getName(), "expandedKey");
                if (!Arrays.constantTimeAreEqual(expanded, encoding))
                {
                    throw new IllegalArgumentException("inconsistent " + mlkemParams.getName() + " private key");
                }

                return mlkemPriv;
            }

            throw new IllegalArgumentException("invalid " + mlkemParams.getName() + " private key");
        }
        else if (Utils.slhdsaParams.containsKey(algOID))
        {
            SLHDSAParameters spParams = Utils.slhdsaParamsLookup(algOID);
            ASN1OctetString slhdsaKey = parseOctetString(keyInfo.getPrivateKey(), spParams.getN() * 4);

            return new SLHDSAPrivateKeyParameters(spParams, slhdsaKey.getOctets());
        }
        else if (
            algOID.equals(CryptoProObjectIdentifiers.gostR3410_2001) ||
                algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) ||
                algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256))
        {
            ASN1Encodable algParameters = requiredParameters(algId, "GOST R 34.10");
            GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(algParameters);
            ECGOST3410Parameters ecSpec = null;
            BigInteger d = null;
            ASN1Primitive p = algParameters.toASN1Primitive();
            if (p instanceof ASN1Sequence && ASN1Sequence.getInstance(p).size() >= 1 && ASN1Sequence.getInstance(p).size() <= 3)
            {
                X9ECParameters ecP = ECGOST3410NamedCurves.getByOIDX9(gostParams.getPublicKeyParamSet());

                ecSpec = new ECGOST3410Parameters(
                    new ECNamedDomainParameters(
                        gostParams.getPublicKeyParamSet(), ecP),
                    gostParams.getPublicKeyParamSet(),
                    gostParams.getDigestParamSet(),
                    gostParams.getEncryptionParamSet());

                int privateKeyLength = keyInfo.getPrivateKeyLength();

                if (privateKeyLength == 32 || privateKeyLength == 64)
                {
                    d = new BigInteger(1, Arrays.reverse(keyInfo.getPrivateKey().getOctets()));
                }
                else
                {
                    ASN1Encodable privKey = keyInfo.parsePrivateKey();
                    if (privKey instanceof ASN1Integer)
                    {
                        d = ASN1Integer.getInstance(privKey).getPositiveValue();
                    }
                    else
                    {
                        byte[] dVal = Arrays.reverse(ASN1OctetString.getInstance(privKey).getOctets());
                        d = new BigInteger(1, dVal);
                    }
                }
            }
            else
            {
                X962Parameters params = X962Parameters.getInstance(algId.getParameters());

                if (params.isNamedCurve())
                {
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
                    X9ECParameters ecP = ECNamedCurveTable.getByOID(oid);

                    ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(oid, ecP),
                        gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
                        gostParams.getEncryptionParamSet());
                }
                else if (params.isImplicitlyCA())
                {
                    ecSpec = null;
                }
                else
                {
                    X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
                    ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(algOID, ecP),
                        gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
                        gostParams.getEncryptionParamSet());
                }

                ASN1Encodable privKey = keyInfo.parsePrivateKey();
                if (privKey instanceof ASN1Integer)
                {
                    ASN1Integer derD = ASN1Integer.getInstance(privKey);

                    d = derD.getValue();
                }
                else
                {
                    ECPrivateKey ec = ECPrivateKey.getInstance(privKey);

                    d = ec.getKey();
                }

            }

            return new ECPrivateKeyParameters(
                d,
                new ECGOST3410Parameters(
                    ecSpec,
                    gostParams.getPublicKeyParamSet(),
                    gostParams.getDigestParamSet(),
                    gostParams.getEncryptionParamSet()));

        }
        else
        {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    /**
     * So it seems for the new PQC algorithms, there's a couple of approaches to what goes in the OCTET STRING
     */
    private static ASN1OctetString parseOctetString(ASN1OctetString octStr, int expectedLength)
        throws IOException
    {
        byte[] data = octStr.getOctets();
        //
        // it's the right length for a RAW encoding, just return it.
        //
        if (data.length == expectedLength)
        {
            return octStr;
        }

        //
        // possible internal OCTET STRING, possibly long form with or without the internal OCTET STRING
        ASN1OctetString obj = Utils.parseOctetData(data);

        if (obj != null)
        {
            return ASN1OctetString.getInstance(obj);
        }

        return octStr;
    }
    
    // FIPS 204 sec. 4, Table 2: the expanded private key size of each parameter set (the HashML-DSA sets
    // share them)
    private static int mldsaExpandedKeyLength(MLDSAParameters params)
    {
        String name = params.getName();
        if (name.startsWith("ml-dsa-44"))
        {
            return 2560;
        }
        if (name.startsWith("ml-dsa-65"))
        {
            return 4032;
        }
        if (name.startsWith("ml-dsa-87"))
        {
            return 4896;
        }
        return -1;
    }

    // FIPS 203 sec. 8, Table 3: the decapsulation key size of each parameter set
    private static int mlkemExpandedKeyLength(MLKEMParameters params)
    {
        String name = params.getName();
        if (name.equals("ML-KEM-512"))
        {
            return 1632;
        }
        if (name.equals("ML-KEM-768"))
        {
            return 2400;
        }
        if (name.equals("ML-KEM-1024"))
        {
            return 3168;
        }
        return -1;
    }

    /**
     * Parse the privateKey OCTET STRING of an ML-DSA (RFC 9881 sec. 6) or ML-KEM (RFC 9935 sec. 6) PrivateKeyInfo,
     * whose content is the DER of
     * <pre>
     *   CHOICE { seed [0] OCTET STRING (SIZE (seedLength)), expandedKey OCTET STRING (SIZE (n)),
     *            both SEQUENCE { seed OCTET STRING (SIZE (seedLength)), expandedKey OCTET STRING (SIZE (n)) } }
     * </pre>
     * The tag says which arm is present, so the seed arm is returned as the {@link ASN1TaggedObject} for the
     * caller to check its length against, the expandedKey arm as an {@link ASN1OctetString} and both as an
     * {@link ASN1Sequence}. Three pre-RFC forms, which the drafts this library followed before the RFCs were
     * published produced, are still read and come back as an {@link ASN1OctetString} too: the raw seed as the
     * OCTET STRING's content, the raw expanded key as its content, and the seed in an untagged inner OCTET STRING.
     * <p>
     * The raw forms are recognised by their length before anything is parsed. Their content is random, so it can
     * begin with bytes that read as a tag and a length exactly covering the rest - about once in 2^24 for an
     * expanded key - and only the length tells them apart reliably: no DER encoding of a CHOICE arm is as long as
     * the raw seed or the raw expanded key.
     */
    private static ASN1Primitive parsePrivateKeyChoice(ASN1OctetString octStr, int seedLength, int expandedKeyLength,
        String algorithmName)
    {
        byte[] data = octStr.getOctets();

        // pre-RFC: the raw seed or the raw expanded key as the content of the OCTET STRING
        if (data.length == seedLength || data.length == expandedKeyLength)
        {
            return octStr;
        }

        if (data.length == 0 || Utils.isRaw(data))
        {
            // not a DER value, and neither raw form's length: returned for the key constructor to reject by its length
            return octStr;
        }

        // RFC form: the tag of the CHOICE arm, and nothing else, says which arm this is; any context-specific
        // tag is examined so that one other than [0] is reported as such
        if ((data[0] & 0xC0) == BERTags.CONTEXT_SPECIFIC)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(data);
            if (!tagged.hasContextTag(0))
            {
                throw new IllegalArgumentException("invalid " + algorithmName + " private key: unexpected tag");
            }
            return tagged;
        }

        // RFC form: expandedKey as an OCTET STRING or both as a SEQUENCE; an untagged OCTET STRING of the seed's
        // length is the pre-RFC form of the seed, a length no expandedKey can have
        ASN1Primitive obj = Utils.parseData(data);
        if (obj instanceof ASN1OctetString || obj instanceof ASN1Sequence)
        {
            return obj;
        }

        throw new IllegalArgumentException("invalid " + algorithmName + " private key");
    }

    private static void checkChoiceLength(byte[] value, int expectedLength, String algorithmName, String field)
    {
        if (value.length != expectedLength)
        {
            throw new IllegalArgumentException("invalid " + algorithmName + " private key: " + field + " must be "
                + expectedLength + " bytes, not " + value.length);
        }
    }

    // the algorithm parameters the key cannot be interpreted without
    private static ASN1Encodable requiredParameters(AlgorithmIdentifier algId, String algorithmName)
    {
        ASN1Encodable parameters = algId.getParameters();
        if (parameters == null)
        {
            throw new IllegalArgumentException(algorithmName + " private key requires algorithm parameters");
        }
        return parameters;
    }

    private static byte[] getRawKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
    }
}
