package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class GOST3410KeyPairTest
    extends SimpleTest
{
    private void gost2012MismatchTest()
        throws Exception
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

        KeyPair kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetB"));

        kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetC"));

        kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

        kp = keyPair.generateKeyPair();

        testWrong512(kp);
    }

    /**
     * github #611: an ECGOST3410-2012 key generated on one of the (256-bit) GOST R 34.10-2001
     * curves must carry the GOST R 34.11-2012-256 digest OID, not the legacy GOST R 34.11-94 one.
     */
    private void gost2012DigestOidTest()
        throws Exception
    {
        // 2001-named curves are valid for GOST-2012-256 and must report the 2012-256 digest.
        checkDigestOid(new GOST3410ParameterSpec("GostR3410-2001-CryptoPro-A"),
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        checkDigestOid(new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"),
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        checkDigestOid(new ECGenParameterSpec("GostR3410-2001-CryptoPro-XchA"),
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);

        // the native 2012 curves must keep reporting their own digest OIDs unchanged.
        checkDigestOid(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"),
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        checkDigestOid(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"),
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
    }

    private void checkDigestOid(java.security.spec.AlgorithmParameterSpec spec, ASN1ObjectIdentifier expected)
        throws Exception
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

        keyPair.initialize(spec);

        KeyPair kp = keyPair.generateKeyPair();

        ASN1ObjectIdentifier pubDigest = ((BCECGOST3410_2012PublicKey)kp.getPublic())
            .getGostParams().getDigestParamSet();
        isTrue("public key digest OID mismatch for " + spec + ": " + pubDigest, expected.equals(pubDigest));

        // the digest OID must also survive encoding of both the public and the private key.
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        ASN1ObjectIdentifier encPubDigest = GOST3410PublicKeyAlgParameters.getInstance(
            spki.getAlgorithm().getParameters()).getDigestParamSet();
        isTrue("encoded public key digest OID mismatch: " + encPubDigest, expected.equals(encPubDigest));

        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1ObjectIdentifier encPrivDigest = GOST3410PublicKeyAlgParameters.getInstance(
            pki.getPrivateKeyAlgorithm().getParameters()).getDigestParamSet();
        isTrue("encoded private key digest OID mismatch: " + encPrivDigest, expected.equals(encPrivDigest));
    }

    /**
     * GOST 34.10-2018 is the interstate re-adoption of GOST R 34.10-2012 and is registered
     * purely as a set of "-2018" aliases onto the existing 2012 implementations. Prove the
     * aliases resolve and that a signature made through a "-2018" name verifies through the
     * matching "-2012" name (and vice versa) since they are the same algorithm.
     */
    private void gost2018AliasTest()
        throws Exception
    {
        gost2018AliasRoundtrip("Tc26-Gost-3410-12-256-paramSetA", "ECGOST3410-2018-256", "ECGOST3410-2012-256");
        gost2018AliasRoundtrip("Tc26-Gost-3410-12-512-paramSetA", "ECGOST3410-2018-512", "ECGOST3410-2012-512");

        // dotted "GOST-3410-2018-NNN" spellings must resolve to the same Signature too.
        isTrue("GOST-3410-2018-256 alias", Signature.getInstance("GOST-3410-2018-256", "BC") != null);
        isTrue("GOST-3410-2018-512 alias", Signature.getInstance("GOST-3410-2018-512", "BC") != null);

        // KeyAgreement aliases must resolve.
        isTrue("KeyAgreement ECGOST3410-2018-256 alias",
            javax.crypto.KeyAgreement.getInstance("ECGOST3410-2018-256", "BC") != null);
        isTrue("KeyAgreement ECGOST3410-2018-512 alias",
            javax.crypto.KeyAgreement.getInstance("ECGOST3410-2018-512", "BC") != null);
    }

    private void gost2018AliasRoundtrip(String paramSet, String name2018, String name2012)
        throws Exception
    {
        byte[] msg = toByteArray("the quick brown fox jumps over the lazy dog");

        // the KeyPairGenerator "-2018" alias must produce a usable 2012 key pair.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2018", "BC");
        kpg.initialize(new ECGenParameterSpec(paramSet));
        KeyPair kp = kpg.generateKeyPair();

        // sign through the 2018 name, verify through the 2012 name.
        Signature sign2018 = Signature.getInstance(name2018, "BC");
        sign2018.initSign(kp.getPrivate());
        sign2018.update(msg);
        byte[] sig2018 = sign2018.sign();

        Signature verify2012 = Signature.getInstance(name2012, "BC");
        verify2012.initVerify(kp.getPublic());
        verify2012.update(msg);
        isTrue(name2018 + " signature did not verify under " + name2012, verify2012.verify(sig2018));

        // sign through the 2012 name, verify through the 2018 name.
        Signature sign2012 = Signature.getInstance(name2012, "BC");
        sign2012.initSign(kp.getPrivate());
        sign2012.update(msg);
        byte[] sig2012 = sign2012.sign();

        Signature verify2018 = Signature.getInstance(name2018, "BC");
        verify2018.initVerify(kp.getPublic());
        verify2018.update(msg);
        isTrue(name2012 + " signature did not verify under " + name2018, verify2018.verify(sig2012));
    }

    private void testWrong512(KeyPair kp)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        Signature sig;
        sig = Signature.getInstance("ECGOST3410-2012-512", "BC");

        try
        {
            sig.initSign(kp.getPrivate());

            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key too weak for ECGOST-2012-512", e.getMessage());
        }

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key too weak for ECGOST-2012-512", e.getMessage());
        }
    }

    private void testWrong256(KeyPair kp)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        Signature sig = Signature.getInstance("ECGOST3410-2012-256", "BC");

        try
        {
            sig.initSign(kp.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key out of range for ECGOST-2012-256", e.getMessage());
        }

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key out of range for ECGOST-2012-256", e.getMessage());
        }
    }

    private BigInteger[] decode(
        byte[] encoding)
    {
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        System.arraycopy(encoding, 0, s, 0, 32);

        System.arraycopy(encoding, 32, r, 0, 32);

        BigInteger[] sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
    }

    private Object serializeDeserialize(Object o)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        return oIn.readObject();
    }

    public String getName()
    {
        return "GOST3410/ECGOST3410/ECGOST3410 2012";
    }

    /**
     * A GOST R 34.10-2012 key on a legacy GOST R 34.10-2001 curve (RFC 9215, Section 4.2), as the
     * lightweight factories now encode it, must come back through the JCE as a 2012 key that still
     * encodes under the 2012 algorithm OID and signs with the 2012 signature.
     */
    private void gost2012CryptoProCurveEncodingTest()
        throws Exception
    {
        ASN1ObjectIdentifier curveOid = CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA;
        ASN1ObjectIdentifier digestOid = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

        ECNamedDomainParameters domainParameters = new ECNamedDomainParameters(curveOid,
            ECGOST3410NamedCurves.getByOIDX9(curveOid));
        ECGOST3410Parameters gostParameters = new ECGOST3410Parameters(domainParameters, curveOid, digestOid, null);

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(gostParameters, new SecureRandom()));
        AsymmetricCipherKeyPair lwKp = generator.generateKeyPair();

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(lwKp.getPublic());
        PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(lwKp.getPrivate());
        isEquals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, spki.getAlgorithm().getAlgorithm());
        isEquals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, pki.getPrivateKeyAlgorithm().getAlgorithm());

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));

        isTrue("not a 2012 public key: " + pub.getClass(), pub instanceof BCECGOST3410_2012PublicKey);
        isTrue("not a 2012 private key: " + priv.getClass(), priv instanceof BCECGOST3410_2012PrivateKey);
        isEquals(curveOid, ((BCECGOST3410_2012PublicKey)pub).getGostParams().getPublicKeyParamSet());
        isEquals(digestOid, ((BCECGOST3410_2012PublicKey)pub).getGostParams().getDigestParamSet());

        // the provider's own key-info bridge must agree with the KeyFactory
        isTrue(BouncyCastleProvider.getPublicKey(spki) instanceof BCECGOST3410_2012PublicKey);
        isTrue(BouncyCastleProvider.getPrivateKey(pki) instanceof BCECGOST3410_2012PrivateKey);

        // re-encoding through the JCE keys must keep the 2012 algorithm OID
        isEquals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
            SubjectPublicKeyInfo.getInstance(pub.getEncoded()).getAlgorithm().getAlgorithm());
        isEquals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
            PrivateKeyInfo.getInstance(priv.getEncoded()).getPrivateKeyAlgorithm().getAlgorithm());

        byte[] msg = toByteArray("the quick brown fox jumps over the lazy dog");

        Signature sig = Signature.getInstance("ECGOST3410-2012-256", "BC");
        sig.initSign(priv);
        sig.update(msg);
        byte[] s = sig.sign();

        sig.initVerify(pub);
        sig.update(msg);
        isTrue("2012-256 signature did not verify", sig.verify(s));
    }

    public void performTest()
        throws Exception
    {
        gost2012MismatchTest();
        gost2012DigestOidTest();
        gost2012CryptoProCurveEncodingTest();
        gost2018AliasTest();
    }

    protected byte[] toByteArray(String input)
    {
        byte[] bytes = new byte[input.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }

        return bytes;
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOST3410KeyPairTest());
    }
}
