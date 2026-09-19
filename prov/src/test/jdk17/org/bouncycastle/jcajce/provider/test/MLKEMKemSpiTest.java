package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * ML-KEM through the JDK's own {@link javax.crypto.KEM} API (JEP 452), which is served by the
 * MLKEMSpi / MLKEMEncapsulatorSpi / MLKEMDecapsulatorSpi multi-release overlay under
 * src/main/jdk17.
 * <p>
 * This lives in its own source set because the normal test source set compiles at release 8,
 * where javax.crypto.KEM does not exist. It is the only coverage of that overlay: the SPIs are
 * shadowed by the multi-release jar rather than reachable from src/main/java, so a class-path
 * test of the ordinary provider entry points never touches them. An untested overlay is how the
 * encapsulator came to be calling a generator from the deprecated org.bouncycastle.pqc.crypto
 * tree after the key classes had moved to org.bouncycastle.crypto.params - it compiled, because
 * both types existed, and threw ClassCastException on every encapsulate().
 * </p>
 */
public class MLKEMKemSpiTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The round trip has to agree for every parameter set, and the encapsulation has to be the
     * size FIPS 203 gives that set - a KEM that returned a fixed or empty buffer would still
     * "agree" with itself, so the length is checked too.
     */
    public void testRoundTripForEachParameterSet()
        throws Exception
    {
        implRoundTrip(MLKEMParameterSpec.ml_kem_512, 768);
        implRoundTrip(MLKEMParameterSpec.ml_kem_768, 1088);
        implRoundTrip(MLKEMParameterSpec.ml_kem_1024, 1568);
    }

    private void implRoundTrip(MLKEMParameterSpec paramSpec, int expectedEncapsulationLength)
        throws Exception
    {
        KeyPair kp = generate(paramSpec);

        KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic(), null, null);
        KEM.Encapsulated encapsulated = enc.encapsulate();

        assertEquals("encapsulation size for " + paramSpec.getName(),
            expectedEncapsulationLength, encapsulated.encapsulation().length);

        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate(), null);
        SecretKey received = dec.decapsulate(encapsulated.encapsulation());

        assertEquals(encapsulated.key().getAlgorithm(), received.getAlgorithm());
        assertTrue("shared secret disagreed for " + paramSpec.getName(),
            Arrays.areEqual(encapsulated.key().getEncoded(), received.getEncoded()));
        assertEquals(32, received.getEncoded().length);
    }

    /**
     * The KTSParameterSpec path wraps the shared secret for a named algorithm, which is a
     * different route through the encapsulator than the null spec above.
     */
    public void testRoundTripWithKTSParameterSpec()
        throws Exception
    {
        implKTSRoundTrip("AES", 256);
        implKTSRoundTrip("AES-KWP", 256);
        implKTSRoundTrip("Camellia", 256);
        implKTSRoundTrip("Camellia-KWP", 256);
        implKTSRoundTrip("SEED", 128);
        implKTSRoundTrip("ARIA", 256);
        implKTSRoundTrip("ARIA-KWP", 256);
    }

    private void implKTSRoundTrip(String algorithm, int keySizeInBits)
        throws Exception
    {
        KeyPair kp = generate(MLKEMParameterSpec.ml_kem_768);

        KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder(algorithm, keySizeInBits).build();

        KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic(), ktsSpec, null);
        KEM.Encapsulated encapsulated = enc.encapsulate();

        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey received = dec.decapsulate(encapsulated.encapsulation());

        assertTrue("shared secret disagreed for " + algorithm,
            Arrays.areEqual(encapsulated.key().getEncoded(), received.getEncoded()));
        assertEquals("derived key size for " + algorithm,
            keySizeInBits / 8, received.getEncoded().length);
    }

    /**
     * NEGATIVE. A damaged encapsulation must not yield the sender's secret.
     * <p>
     * ML-KEM does not reject it: FIPS 203 specifies implicit rejection, so decapsulation returns
     * a pseudorandom key derived from the private key's z value instead of failing. Asserting a
     * throw here would be asserting the wrong contract, so what is checked is that the recovered
     * secret DIFFERS - which is what actually stops a tampered ciphertext being usable, and what
     * an implementation that ignored the ciphertext bits would fail.
     * </p>
     */
    public void testTamperedEncapsulationYieldsADifferentSecret()
        throws Exception
    {
        KeyPair kp = generate(MLKEMParameterSpec.ml_kem_768);

        KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        KEM.Encapsulated encapsulated = kem.newEncapsulator(kp.getPublic(), null, null).encapsulate();
        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate(), null);

        byte[] encapsulation = encapsulated.encapsulation();

        for (int i = 0; i < encapsulation.length; i += 257)
        {
            byte[] damaged = Arrays.clone(encapsulation);
            damaged[i] ^= 0x01;

            SecretKey recovered = dec.decapsulate(damaged);

            assertFalse("bit flip at " + i + " still recovered the sender's secret",
                Arrays.areEqual(encapsulated.key().getEncoded(), recovered.getEncoded()));
        }
    }

    /**
     * NEGATIVE. A decapsulator holding the wrong private key must not recover the secret.
     */
    public void testWrongPrivateKeyYieldsADifferentSecret()
        throws Exception
    {
        KeyPair kp = generate(MLKEMParameterSpec.ml_kem_768);
        KeyPair other = generate(MLKEMParameterSpec.ml_kem_768);

        KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        KEM.Encapsulated encapsulated = kem.newEncapsulator(kp.getPublic(), null, null).encapsulate();

        SecretKey recovered = kem.newDecapsulator(other.getPrivate(), null)
            .decapsulate(encapsulated.encapsulation());

        assertFalse("the wrong private key recovered the secret",
            Arrays.areEqual(encapsulated.key().getEncoded(), recovered.getEncoded()));
    }

    /**
     * NEGATIVE, length boundaries. The size check has to fire on each side of the real length and
     * on the degenerate inputs, not merely somewhere.
     */
    public void testEncapsulationLengthIsChecked()
        throws Exception
    {
        KeyPair kp = generate(MLKEMParameterSpec.ml_kem_768);

        KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate(), null);

        int[] badLengths = new int[]{ 0, 1, 1087, 1089, 2176 };

        for (int i = 0; i != badLengths.length; i++)
        {
            try
            {
                dec.decapsulate(new byte[badLengths[i]]);
                fail("accepted an encapsulation of " + badLengths[i] + " bytes");
            }
            catch (DecapsulateException e)
            {
                assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().contains("incorrect encapsulation size"));
            }
        }
    }

    private KeyPair generate(MLKEMParameterSpec paramSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        kpg.initialize(paramSpec, new SecureRandom());

        return kpg.generateKeyPair();
    }
}
