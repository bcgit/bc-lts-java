package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * Zeroization coverage for the {@link javax.security.auth.Destroyable} support on the ML-DSA /
 * ML-KEM / SLH-DSA lightweight parameter classes.
 * <p>
 * {@link PQCKeyDestructionTest} covers the JCA-level contract (isDestroyed() flips, the accessors
 * and serialization refuse afterwards). This class covers what that cannot see: a {@code destroy()}
 * which only flips a flag - without actually clearing the key material - satisfies every
 * "isDestroyed() is true and the accessors throw" check. So each algorithm is verified to have
 * genuinely zeroized its secret arrays, observed through a second live reference to the same arrays:
 * <ul>
 * <li>ML-DSA / ML-KEM: {@code getParametersWithFormat} / {@code withPreferredFormat} return a new
 * parameters object that <em>shares</em> the underlying arrays and carries its own destroyed flag,
 * so the derived object's accessors still work and expose the zeroized contents. This doubles as
 * coverage for the shared-array caveat called out in the {@code destroy()} javadoc.</li>
 * <li>SLH-DSA: the public {@code (params, skSeed, prf, pkSeed, pkRoot)} constructor retains the
 * caller's arrays rather than copying them, so the caller's own arrays are inspected directly.</li>
 * </ul>
 */
public class PQCPrivateKeyDestroyTest
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

    public void testMLKEMParametersZeroized()
        throws Exception
    {
        MLKEMPrivateKeyParameters params = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
            generatePrivateEncoding("ML-KEM", MLKEMParameterSpec.ml_kem_768));

        // a format other than the current one, so a genuinely new (array-sharing) object comes back
        assertEquals("expected BOTH as the decoded preferred format",
            MLKEMPrivateKeyParameters.BOTH, params.getPreferredFormat());
        MLKEMPrivateKeyParameters shared = params.withPreferredFormat(MLKEMPrivateKeyParameters.EXPANDED_KEY);
        assertNotSame("withPreferredFormat returned the same object", params, shared);

        byte[] sBefore = shared.getS();
        assertFalse("s is all zeroes before destroy", Arrays.areAllZeroes(sBefore, 0, sBefore.length));

        params.destroy();

        assertTrue("params not marked destroyed", params.isDestroyed());
        assertFalse("derived object should carry its own flag", shared.isDestroyed());

        // the derived object is still live, so it can be read - and what it exposes must be zeroized,
        // which a flag-only destroy() would fail.
        byte[] sAfter = shared.getS();
        assertEquals("s changed length", sBefore.length, sAfter.length);
        assertTrue("s was not zeroized by destroy()", Arrays.areAllZeroes(sAfter, 0, sAfter.length));

        byte[] rho = shared.getRho();
        assertTrue("rho was not zeroized by destroy()", Arrays.areAllZeroes(rho, 0, rho.length));
        byte[] hpk = shared.getHPK();
        assertTrue("hpk was not zeroized by destroy()", Arrays.areAllZeroes(hpk, 0, hpk.length));

        checkAccessorsRefused(params);
    }

    public void testMLDSAParametersZeroized()
        throws Exception
    {
        MLDSAPrivateKeyParameters params = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
            generatePrivateEncoding("ML-DSA", MLDSAParameterSpec.ml_dsa_65));

        assertEquals("expected BOTH as the decoded preferred format",
            MLDSAPrivateKeyParameters.BOTH, params.getPreferredFormat());
        MLDSAPrivateKeyParameters shared = params.getParametersWithFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY);
        assertNotSame("getParametersWithFormat returned the same object", params, shared);

        byte[] s1Before = shared.getS1();
        assertFalse("s1 is all zeroes before destroy", Arrays.areAllZeroes(s1Before, 0, s1Before.length));

        params.destroy();

        assertTrue("params not marked destroyed", params.isDestroyed());
        assertFalse("derived object should carry its own flag", shared.isDestroyed());

        byte[] s1After = shared.getS1();
        assertEquals("s1 changed length", s1Before.length, s1After.length);
        assertTrue("s1 was not zeroized by destroy()", Arrays.areAllZeroes(s1After, 0, s1After.length));

        byte[] k = shared.getK();
        assertTrue("k was not zeroized by destroy()", Arrays.areAllZeroes(k, 0, k.length));
        byte[] s2 = shared.getS2();
        assertTrue("s2 was not zeroized by destroy()", Arrays.areAllZeroes(s2, 0, s2.length));

        checkAccessorsRefused(params);
    }

    public void testSLHDSAParametersZeroized()
    {
        SLHDSAParameters parameters = SLHDSAParameters.sha2_128s;
        int n = parameters.getN();

        // The constructor retains these arrays rather than copying them, so destroy() must be
        // observable here.
        byte[] skSeed = nonZeroBytes(n, (byte)0x11);
        byte[] prf = nonZeroBytes(n, (byte)0x22);
        byte[] pkSeed = nonZeroBytes(n, (byte)0x33);
        byte[] pkRoot = nonZeroBytes(n, (byte)0x44);

        SLHDSAPrivateKeyParameters params =
            new SLHDSAPrivateKeyParameters(parameters, skSeed, prf, pkSeed, pkRoot);

        assertFalse("fresh params report destroyed", params.isDestroyed());
        byte[] seedBefore = params.getSeed();
        assertFalse("seed is all zeroes before destroy", Arrays.areAllZeroes(seedBefore, 0, seedBefore.length));

        params.destroy();

        assertTrue("params not marked destroyed", params.isDestroyed());

        assertTrue("skSeed was not zeroized by destroy()", Arrays.areAllZeroes(skSeed, 0, skSeed.length));
        assertTrue("prf was not zeroized by destroy()", Arrays.areAllZeroes(prf, 0, prf.length));
        assertTrue("pkSeed was not zeroized by destroy()", Arrays.areAllZeroes(pkSeed, 0, pkSeed.length));
        assertTrue("pkRoot was not zeroized by destroy()", Arrays.areAllZeroes(pkRoot, 0, pkRoot.length));

        try
        {
            params.getSeed();
            fail("getSeed() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        try
        {
            params.getPrf();
            fail("getPrf() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        try
        {
            params.getEncoded();
            fail("getEncoded() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // idempotent
        params.destroy();
        assertTrue(params.isDestroyed());
    }

    private void checkAccessorsRefused(MLKEMPrivateKeyParameters params)
    {
        try
        {
            params.getS();
            fail("getS() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        try
        {
            params.getEncoded();
            fail("getEncoded() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        params.destroy();
        assertTrue(params.isDestroyed());
    }

    private void checkAccessorsRefused(MLDSAPrivateKeyParameters params)
    {
        try
        {
            params.getS1();
            fail("getS1() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        try
        {
            params.getEncoded();
            fail("getEncoded() succeeded after destroy");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        params.destroy();
        assertTrue(params.isDestroyed());
    }

    private byte[] generatePrivateEncoding(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);
        kpg.initialize(spec, new SecureRandom());

        return kpg.generateKeyPair().getPrivate().getEncoded();
    }

    private static byte[] nonZeroBytes(int len, byte fill)
    {
        byte[] rv = new byte[len];
        Arrays.fill(rv, fill);

        return rv;
    }
}
