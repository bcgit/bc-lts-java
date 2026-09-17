package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

/**
 * The EdDSA and XDH SPIs are shadowed on JDK 11/15+ by multi-release overlays under
 * prov/src/main/jdk1.11 and jdk1.15. Those overlays handle the BC key classes and the JDK's own
 * EdECKey/XECKey types, and have twice been found to have dropped something the base class in
 * src/main/java does - the OpenSSH passphrase, and the HKDF salt.
 * <p>
 * This pins the remaining base-class behaviour that is easiest to lose: a key from some other
 * provider, which is neither a BC key nor a JDK EdECKey and offers only its encoding, must still
 * be usable. A classes-directory test run cannot see a regression here, because the base class is
 * what loads there - this only fails against the built multi-release jar.
 */
public class EdECForeignKeyTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testForeignEd25519KeyAccepted()
        throws Exception
    {
        checkForeignKeyRoundTrip("Ed25519");
    }

    public void testForeignEd448KeyAccepted()
        throws Exception
    {
        checkForeignKeyRoundTrip("Ed448");
    }

    private void checkForeignKeyRoundTrip(String algorithm)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(algorithm, "BC").generateKeyPair();

        PrivateKey priv = new ForeignPrivateKey(algorithm, kp.getPrivate().getEncoded());
        PublicKey pub = new ForeignPublicKey(algorithm, kp.getPublic().getEncoded());

        byte[] msg = Strings.toByteArray("the quick brown fox");

        Signature signer = Signature.getInstance(algorithm, "BC");
        signer.initSign(priv);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(algorithm, "BC");
        verifier.initVerify(pub);
        verifier.update(msg);
        assertTrue(algorithm + ": foreign key signature did not verify", verifier.verify(sig));

        // and the negative path: a damaged message must not verify, so the check above cannot be
        // passing because verify() is simply returning true
        byte[] damaged = Strings.toByteArray("the quick brown fix");

        Signature negative = Signature.getInstance(algorithm, "BC");
        negative.initVerify(pub);
        negative.update(damaged);
        assertFalse(algorithm + ": modified message verified", negative.verify(sig));
    }

    private static class ForeignPrivateKey
        implements PrivateKey
    {
        private final String algorithm;
        private final byte[] encoding;

        ForeignPrivateKey(String algorithm, byte[] encoding)
        {
            this.algorithm = algorithm;
            this.encoding = encoding;
        }

        public String getAlgorithm()
        {
            return algorithm;
        }

        public String getFormat()
        {
            return "PKCS#8";
        }

        public byte[] getEncoded()
        {
            return encoding.clone();
        }
    }

    private static class ForeignPublicKey
        implements PublicKey
    {
        private final String algorithm;
        private final byte[] encoding;

        ForeignPublicKey(String algorithm, byte[] encoding)
        {
            this.algorithm = algorithm;
            this.encoding = encoding;
        }

        public String getAlgorithm()
        {
            return algorithm;
        }

        public String getFormat()
        {
            return "X.509";
        }

        public byte[] getEncoded()
        {
            return encoding.clone();
        }
    }
}
