package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Checks the key algorithm OID chosen when encoding ECGOST3410 keys as SubjectPublicKeyInfo /
 * PrivateKeyInfo. A legacy GOST R 34.10-2001 parameter set combined with a GOST R 34.11-2012 digest
 * must encode as GOST R 34.10-2012 (RFC 9215, Section 4.2), while the same curve with a GOST R 34.11-94
 * digest remains GOST R 34.10-2001 (RFC 4491, Section 2.3.2). Also covers the OPTIONAL digestParamSet
 * of GostR3410-2012-PublicKeyParameters.
 */
public class ECGOST3410KeyEncodingTest
    extends SimpleTest
{
    private static final ASN1Set ATTRIBUTES = new DERSet(
        new Attribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERSet(new DERBMPString("ECGOST3410"))));

    public String getName()
    {
        return "ECGOST3410KeyEncoding";
    }

    public void performTest()
        throws Exception
    {
        // Legacy CryptoPro parameter sets with a GOST R 34.11-2012 digest (RFC 9215, Section 4.2)
        checkKeyAlgID(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A,
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        checkKeyAlgID(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA,
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);

        // Legacy CryptoPro parameter sets with a GOST R 34.11-94 digest (RFC 4491, Section 2.3.2)
        checkKeyAlgID(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A,
            CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet,
            CryptoProObjectIdentifiers.gostR3410_2001);
        checkKeyAlgID(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A,
            CryptoProObjectIdentifiers.gostR3411_94_TestParamSet,
            CryptoProObjectIdentifiers.gostR3410_2001);

        // TC26 parameter sets
        checkKeyAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        checkKeyAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);

        // TC26 parameter sets with digestParamSet omitted (RFC 9215, Section 4.2: MUST for 256-B/C/D,
        // SHOULD for 256-A and 512-bit keys)
        checkKeyAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB, null,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        checkKeyAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, null,
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);

        checkGost2012CryptoProSpki();
        checkUnrecognisedDigestParamSet();
        checkAlgParametersSequenceSizes();
    }

    private void checkKeyAlgID(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet,
        ASN1ObjectIdentifier expectedAlgOid)
        throws Exception
    {
        AsymmetricCipherKeyPair keyPair = generateKeyPair(publicKeyParamSet, digestParamSet);
        ECPublicKeyParameters pub = (ECPublicKeyParameters)keyPair.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)keyPair.getPrivate();
        int fieldSize = pub.getParameters().getCurve().getFieldElementEncodingLength();

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);
        checkAlgorithmIdentifier(spki.getAlgorithm(), expectedAlgOid, publicKeyParamSet, digestParamSet);
        isEquals("public key length", 2 * fieldSize,
            ASN1OctetString.getInstance(spki.parsePublicKey()).getOctets().length);

        PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(priv, ATTRIBUTES);
        checkAlgorithmIdentifier(pki.getPrivateKeyAlgorithm(), expectedAlgOid, publicKeyParamSet, digestParamSet);
        isEquals("private key length", fieldSize,
            ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets().length);
        isTrue("attributes not preserved", ATTRIBUTES.equals(pki.getAttributes()));

        // Round trip: the key material and the algorithm OID must survive decoding and re-encoding
        ECPublicKeyParameters decodedPub = (ECPublicKeyParameters)PublicKeyFactory.createKey(spki.getEncoded());
        isTrue("public key Q mismatch", pub.getQ().equals(decodedPub.getQ()));
        isEquals("re-encoded public key algorithm", expectedAlgOid,
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(decodedPub).getAlgorithm().getAlgorithm());

        ECPrivateKeyParameters decodedPriv = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(pki.getEncoded());
        isTrue("private key D mismatch", priv.getD().equals(decodedPriv.getD()));
        isEquals("re-encoded private key algorithm", expectedAlgOid,
            PrivateKeyInfoFactory.createPrivateKeyInfo(decodedPriv).getPrivateKeyAlgorithm().getAlgorithm());
    }

    /**
     * The case from bc-csharp issue #707: a GOST R 34.10-2012 key using a legacy CryptoPro parameter set
     * must be encoded with the GOST R 34.10-2012 algorithm OID and RFC 9215 parameters.
     */
    private void checkGost2012CryptoProSpki()
        throws Exception
    {
        ASN1ObjectIdentifier curveOid = CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA;
        ASN1ObjectIdentifier digestOid = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

        AsymmetricCipherKeyPair keyPair = generateKeyPair(curveOid, digestOid);

        byte[] expectedParams = new DERSequence(new ASN1ObjectIdentifier[]{ curveOid, digestOid }).getEncoded();

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
        isEquals("SPKI algorithm", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
            spki.getAlgorithm().getAlgorithm());
        isTrue("SPKI parameters",
            Arrays.areEqual(expectedParams, spki.getAlgorithm().getParameters().toASN1Primitive().getEncoded()));

        PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());
        isEquals("PKCS#8 algorithm", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
            pki.getPrivateKeyAlgorithm().getAlgorithm());
        isTrue("PKCS#8 parameters",
            Arrays.areEqual(expectedParams, pki.getPrivateKeyAlgorithm().getParameters().toASN1Primitive().getEncoded()));
    }

    private void checkUnrecognisedDigestParamSet()
        throws Exception
    {
        // The GOST R 34.11-94 algorithm OID is not a digest parameter set
        AsymmetricCipherKeyPair keyPair = generateKeyPair(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A,
            CryptoProObjectIdentifiers.gostR3411);

        try
        {
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
            fail("unrecognised digestParamSet accepted for public key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage().startsWith("unrecognised GOST R 34.11 digestParamSet"));
        }

        try
        {
            PrivateKeyInfoFactory.createPrivateKeyInfo(keyPair.getPrivate());
            fail("unrecognised digestParamSet accepted for private key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage().startsWith("unrecognised GOST R 34.11 digestParamSet"));
        }
    }

    private void checkAlgParametersSequenceSizes()
        throws Exception
    {
        ASN1ObjectIdentifier publicKeyParamSet = CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A;
        ASN1ObjectIdentifier digestParamSet = CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet;
        ASN1ObjectIdentifier encryptionParamSet = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;

        // One element: digestParamSet omitted (RFC 9215)
        ASN1Sequence oneSeq = new DERSequence(publicKeyParamSet);
        GOST3410PublicKeyAlgParameters one = GOST3410PublicKeyAlgParameters.getInstance(oneSeq);
        isEquals(publicKeyParamSet, one.getPublicKeyParamSet());
        isTrue(one.getDigestParamSet() == null);
        isTrue(one.getEncryptionParamSet() == null);
        isTrue(oneSeq.equals(one.toASN1Primitive()));

        // Two elements: the second is always digestParamSet, never encryptionParamSet
        ASN1Sequence twoSeq = new DERSequence(new ASN1ObjectIdentifier[]{ publicKeyParamSet, digestParamSet });
        GOST3410PublicKeyAlgParameters two = GOST3410PublicKeyAlgParameters.getInstance(twoSeq);
        isEquals(digestParamSet, two.getDigestParamSet());
        isTrue(two.getEncryptionParamSet() == null);
        isTrue(twoSeq.equals(two.toASN1Primitive()));

        // Three elements (RFC 4491)
        ASN1Sequence threeSeq = new DERSequence(
            new ASN1ObjectIdentifier[]{ publicKeyParamSet, digestParamSet, encryptionParamSet });
        GOST3410PublicKeyAlgParameters three = GOST3410PublicKeyAlgParameters.getInstance(threeSeq);
        isEquals(digestParamSet, three.getDigestParamSet());
        isEquals(encryptionParamSet, three.getEncryptionParamSet());
        isTrue(threeSeq.equals(three.toASN1Primitive()));

        // A digestParamSet alongside 256 paramSetB/C/D is accepted on decode (RFC 9215 says to omit it)
        GOST3410PublicKeyAlgParameters legacyB = GOST3410PublicKeyAlgParameters.getInstance(new DERSequence(
            new ASN1ObjectIdentifier[]{ RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256 }));
        isEquals(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, legacyB.getDigestParamSet());

        // Out-of-range sizes
        try
        {
            GOST3410PublicKeyAlgParameters.getInstance(new DERSequence());
            fail("empty sequence accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Bad sequence size: 0", e.getMessage());
        }
        try
        {
            GOST3410PublicKeyAlgParameters.getInstance(new DERSequence(new ASN1ObjectIdentifier[]{
                publicKeyParamSet, digestParamSet, encryptionParamSet, encryptionParamSet }));
            fail("four element sequence accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Bad sequence size: 4", e.getMessage());
        }

        // encryptionParamSet cannot be encoded without digestParamSet
        try
        {
            new GOST3410PublicKeyAlgParameters(publicKeyParamSet, null, encryptionParamSet);
            fail("encryptionParamSet without digestParamSet accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("encryptionParamSet requires digestParamSet", e.getMessage());
        }
    }

    private void checkAlgorithmIdentifier(AlgorithmIdentifier algID, ASN1ObjectIdentifier expectedAlgOid,
        ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet)
    {
        isEquals("algorithm OID", expectedAlgOid, algID.getAlgorithm());

        // An omitted digestParamSet must be absent from the encoding, not encoded as some placeholder
        int expectedCount = digestParamSet == null ? 1 : 2;
        isEquals("parameter count", expectedCount, ASN1Sequence.getInstance(algID.getParameters()).size());

        GOST3410PublicKeyAlgParameters algParams = GOST3410PublicKeyAlgParameters.getInstance(algID.getParameters());
        isEquals("publicKeyParamSet", publicKeyParamSet, algParams.getPublicKeyParamSet());
        isEquals("digestParamSet", digestParamSet, algParams.getDigestParamSet());
        isTrue("encryptionParamSet present", algParams.getEncryptionParamSet() == null);
    }

    private static AsymmetricCipherKeyPair generateKeyPair(ASN1ObjectIdentifier publicKeyParamSet,
        ASN1ObjectIdentifier digestParamSet)
    {
        ECNamedDomainParameters domainParameters = new ECNamedDomainParameters(publicKeyParamSet,
            ECGOST3410NamedCurves.getByOIDX9(publicKeyParamSet));
        ECGOST3410Parameters gostParameters = new ECGOST3410Parameters(domainParameters, publicKeyParamSet,
            digestParamSet, null);

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(gostParameters, new SecureRandom()));
        return generator.generateKeyPair();
    }

    public static void main(String[] args)
    {
        runTest(new ECGOST3410KeyEncodingTest());
    }
}
