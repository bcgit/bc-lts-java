package org.bouncycastle.cms.test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.FixedLengthContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * {@link SignerInfoGenerator#getPredictedEncodedLength} exists so a definite-length (DL) SignedData
 * can be streamed: the SignerInfos trail the content in the encoding, but their length feeds the
 * enclosing headers, which are written before any content flows. The prediction is therefore
 * committed to the wire before the signature exists.
 * <p>
 * A prediction that is merely close is worse than none - the header would declare a length the body
 * never matches - so these tests compare it against the real encoded SignerInfo rather than checking
 * it is non-negative. They also pin the cases where -1 ("cannot be fixed in advance") is the correct
 * answer, since a caller must fall back to indefinite-length encoding there.
 */
public class PredictedEncodedLengthTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testRsaPredictionMatchesActual()
        throws Exception
    {
        checkPredictionExact("SHA256withRSA", "RSA", 2048);
        checkPredictionExact("SHA512withRSA", "RSA", 2048);
        checkPredictionExact("SHA256withRSA", "RSA", 3072);
    }

    public void testEd25519PredictionMatchesActual()
        throws Exception
    {
        checkPredictionExact("Ed25519", "Ed25519", -1);
    }

    /**
     * DER-encoded ECDSA signatures vary in length - the r and s INTEGERs are minimally encoded - so
     * no prediction is possible and the signer must not claim to be fixed-length.
     */
    public void testEcdsaReportsUnpredictable()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("EC", BC).generateKeyPair();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(kp.getPrivate());

        assertFalse("ECDSA must not present as fixed-length", signer instanceof FixedLengthContentSigner);
        assertEquals(-1L, generatorFor(signer, certFor(kp, "SHA256withECDSA"))
            .getPredictedEncodedLength(CMSObjectIdentifiers.data));
    }

    /**
     * Ed448 is a fixed-length signer (114 octets) and, with signed attributes, digests under
     * id-shake256-len (2.16.840.1.101.3.4.2.18) per RFC 8419 sec. 3.1 rather than plain
     * id-shake256 (...2.12). That OID carries its output length in bits as an ASN.1 parameter, so
     * the prediction has to read the parameter instead of consulting a fixed table - this test
     * pins that it does.
     */
    public void testEd448PredictionMatchesActual()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("Ed448", BC).generateKeyPair();
        ContentSigner signer = new JcaContentSignerBuilder("Ed448").setProvider(BC).build(kp.getPrivate());

        assertTrue("Ed448 should present as fixed-length", signer instanceof FixedLengthContentSigner);
        assertEquals("Ed448 signature length", 114, ((FixedLengthContentSigner)signer).getSignatureLength());

        checkPredictionExact("Ed448", "Ed448", -1);
    }

    private void checkPredictionExact(String sigAlg, String keyAlg, int keySize)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, BC);
        if (keySize > 0)
        {
            kpg.initialize(keySize);
        }
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate cert = certFor(kp, sigAlg);

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(kp.getPrivate());
        assertTrue(sigAlg + " should present as fixed-length", signer instanceof FixedLengthContentSigner);

        SignerInfoGenerator sigGen = generatorFor(signer, cert);

        long predicted = sigGen.getPredictedEncodedLength(CMSObjectIdentifiers.data);
        assertTrue(sigAlg + ": no prediction available", predicted > 0);

        OutputStream sOut = sigGen.getCalculatingOutputStream();
        sOut.write("the quick brown fox jumps over the lazy dog".getBytes("US-ASCII"));
        sOut.close();

        SignerInfo info = sigGen.generate(CMSObjectIdentifiers.data);
        int actual = info.getEncoded(ASN1Encoding.DL).length;

        assertEquals(sigAlg + ": predicted SignerInfo length does not match the encoding",
            actual, predicted);
    }

    private SignerInfoGenerator generatorFor(ContentSigner signer, X509Certificate cert)
        throws Exception
    {
        return new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(signer, cert);
    }

    private X509Certificate certFor(KeyPair kp, String sigAlg)
        throws Exception
    {
        X500Name dn = new X500Name("CN=Predicted Length Test");
        long now = System.currentTimeMillis();

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(
            new JcaX509v3CertificateBuilder(dn, BigInteger.ONE, new Date(now - 10000),
                new Date(now + 86400000L), dn, kp.getPublic())
                .build(new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(kp.getPrivate())));
    }
}
