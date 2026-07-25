package org.bouncycastle.operator.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A composite signature name is only usable if the OID
 * {@link DefaultSignatureAlgorithmIdentifierFinder} returns for it is one the provider has actually
 * registered a {@code Signature} against. Those two live in different modules - the finder in pkix,
 * the registration driven by {@code CompositeIndex} in prov - and they can disagree silently: the
 * name resolves, a key pair generates, and only the attempt to build a signer fails with
 * "no such algorithm: &lt;oid&gt;".
 * <p>
 * That is exactly what happened for the five suites below, whose hash pairing did not change across
 * draft-ietf-lamps-pq-composite-sigs revisions. The provider registers the plain composite names on
 * the IANA arc, while the finder still bound these five to the older BC arc, so signing by name was
 * impossible. This test walks the whole chain - find the OID, generate a key pair, build a signer,
 * produce a signature - so a future divergence between the two modules fails here rather than in a
 * caller.
 */
public class CompositeSignatureNameResolutionTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * The suites that share a name between the two OID arcs. Every one of these was unusable before
     * the finder was pointed at the IANA arc.
     */
    private static final String[] SHARED_NAME_SUITES =
    {
        "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA44-RSA2048-PKCS15-SHA256",
        "MLDSA44-ED25519-SHA512",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-ED25519-SHA512",
    };

    /**
     * A representative suite whose pairing did change, so it has a name of its own on the IANA arc.
     */
    private static final String[] IANA_ONLY_SUITES =
    {
        "MLDSA65-RSA3072-PSS-SHA512",
        "MLDSA87-ED448-SHAKE256",
    };

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSharedNameSuitesResolveToASignableOid()
        throws Exception
    {
        for (int i = 0; i != SHARED_NAME_SUITES.length; i++)
        {
            checkSignable(SHARED_NAME_SUITES[i]);
        }
    }

    public void testIanaOnlySuitesResolveToASignableOid()
        throws Exception
    {
        for (int i = 0; i != IANA_ONLY_SUITES.length; i++)
        {
            checkSignable(IANA_ONLY_SUITES[i]);
        }
    }

    /**
     * The IANA composite arc is 1.3.6.1.5.5.7.6.*; the older BC arc is 2.16.840.1.114027.80.8.1.*.
     * Pinning the prefix documents which arc these names are expected to emit, so a silent move back
     * shows up as a failure here and not as an interop report from a user.
     */
    public void testSharedNameSuitesEmitTheIanaArc()
    {
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();

        for (int i = 0; i != SHARED_NAME_SUITES.length; i++)
        {
            String name = SHARED_NAME_SUITES[i];
            ASN1ObjectIdentifier oid = finder.find(name).getAlgorithm();

            assertTrue(name + " should resolve on the IANA composite arc, got " + oid,
                oid.toString().startsWith("1.3.6.1.5.5.7.6."));
        }
    }

    private void checkSignable(String algorithmName)
        throws Exception
    {
        ASN1ObjectIdentifier oid = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName).getAlgorithm();
        assertNotNull(algorithmName + ": no OID from the finder", oid);

        KeyPair kp = KeyPairGenerator.getInstance(algorithmName, BC).generateKeyPair();

        ContentSigner signer = new JcaContentSignerBuilder(algorithmName).setProvider(BC).build(kp.getPrivate());

        assertEquals(algorithmName + ": signer algorithm does not match the finder",
            oid, signer.getAlgorithmIdentifier().getAlgorithm());

        signer.getOutputStream().write("the quick brown fox".getBytes("US-ASCII"));
        signer.getOutputStream().close();

        byte[] sig = signer.getSignature();
        assertNotNull(algorithmName + ": no signature produced", sig);
        assertTrue(algorithmName + ": empty signature", sig.length > 0);
    }
}
