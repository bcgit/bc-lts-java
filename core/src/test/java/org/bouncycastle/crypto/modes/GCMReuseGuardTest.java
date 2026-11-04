package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * The GCM encrypt guard against nonce reuse, on the java GCM and on the default GCM (native where
 * the native layer is loaded); both must behave the same.
 * <ul>
 * <li>Once encryption under a nonce has produced output, nothing more is processed under it:
 * the native GCM went on encrypting after doFinal, reusing the keystream.</li>
 * <li>A refused re-init leaves the cipher uninitialised: the java GCM went on encrypting under
 * the old nonce after the reuse refusal was caught.</li>
 * <li>A reset before any keystream has been used leaves the cipher usable.</li>
 * </ul>
 */
public class GCMReuseGuardTest
    extends TestCase
{
    private static final long SEED = new SecureRandom().nextLong();

    private Random random;
    private byte[] key;
    private byte[] nonce;
    private byte[] aad;
    private byte[] p1;
    private byte[] p2;

    public void setUp()
    {
        // seeded so a failing run can be reproduced from the seed in the message.
        random = new Random(SEED);

        key = randomBytes(16 + 8 * random.nextInt(3));
        nonce = randomBytes(12);
        aad = randomBytes(random.nextInt(40));
        p1 = randomBytes(1 + random.nextInt(100));
        p2 = randomBytes(p1.length);
    }

    private String msg(GCMModeCipher c, String what)
    {
        return c.getClass().getSimpleName() + ": " + what + " (seed " + SEED + ")";
    }

    private GCMModeCipher[] ciphers()
    {
        return new GCMModeCipher[]{
            new GCMBlockCipher(new AESEngine()),
            GCMBlockCipher.newInstance(AESEngine.newInstance())
        };
    }

    /**
     * P1, a refused re-init with the same key and nonce, the refusal caught, then P2: P2 must not
     * be encrypted.
     */
    public void testRefusedReinitDoesNotRearm()
        throws Exception
    {
        CipherParameters[] reuses = {
            new AEADParameters(new KeyParameter(key), 128, nonce),
            new AEADParameters(null, 128, nonce),
            new ParametersWithIV(new KeyParameter(key), nonce),
            new ParametersWithIV(null, nonce)
        };

        for (int r = 0; r != reuses.length; r++)
        {
            GCMModeCipher[] cs = ciphers();
            for (int i = 0; i != cs.length; i++)
            {
                GCMModeCipher c = cs[i];
                encrypt(c, new AEADParameters(new KeyParameter(key), 128, nonce), p1);

                try
                {
                    c.init(true, reuses[r]);
                    fail(msg(c, "nonce reuse accepted"));
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals(msg(c, "message"), "cannot reuse nonce for GCM encryption", e.getMessage());
                }

                assertNothingProcessed(c);
            }
        }
    }

    /**
     * An init that fails on a bad key, with the same nonce or another one, must not displace the
     * remembered key and nonce: it would pass the reuse check, as the key differs, and the
     * original pair would then be accepted again.
     */
    public void testBadKeyInitKeepsRememberedPair()
        throws Exception
    {
        int[] badLens = {0, 15, 17, 33};
        for (int b = 0; b != badLens.length; b++)
        {
            byte[][] nonces = {nonce, randomBytes(12)};
            for (int n = 0; n != nonces.length; n++)
            {
                GCMModeCipher[] cs = ciphers();
                for (int i = 0; i != cs.length; i++)
                {
                    GCMModeCipher c = cs[i];
                    encrypt(c, new AEADParameters(new KeyParameter(key), 128, nonce), p1);

                    try
                    {
                        c.init(true, new AEADParameters(new KeyParameter(new byte[badLens[b]]), 128, nonces[n]));
                        fail(msg(c, "bad key accepted: " + badLens[b]));
                    }
                    catch (IllegalArgumentException e)
                    {
                        // expected: java GCM
                    }
                    catch (IllegalStateException e)
                    {
                        // expected: native GCM
                    }
                    assertNothingProcessed(c);

                    CipherParameters[] reuses = {
                        new AEADParameters(new KeyParameter(key), 128, nonce),
                        new ParametersWithIV(new KeyParameter(key), nonce),
                        new AEADParameters(null, 128, nonce)
                    };
                    for (int r = 0; r != reuses.length; r++)
                    {
                        try
                        {
                            c.init(true, reuses[r]);
                            fail(msg(c, "original key and nonce accepted after bad key " + badLens[b]));
                        }
                        catch (IllegalArgumentException e)
                        {
                            assertEquals(msg(c, "message"), "cannot reuse nonce for GCM encryption", e.getMessage());
                        }
                        assertNothingProcessed(c);
                    }

                    // the remembered key is still the original one.
                    byte[] fresh = randomBytes(12);
                    assertTrue(msg(c, "key reuse after bad key"), Arrays.areEqual(
                        encrypt(new GCMBlockCipher(new AESEngine()), new AEADParameters(new KeyParameter(key), 128, fresh), p2),
                        encrypt(c, new AEADParameters(null, 128, fresh), p2)));
                }
            }
        }
    }

    /**
     * A re-init refused for any reason, here a bad MAC size, leaves the cipher refusing to
     * process even though nothing was encrypted under the previous init.
     */
    public void testRefusedInitFailsClosed()
        throws Exception
    {
        GCMModeCipher[] cs = ciphers();
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            c.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
            try
            {
                c.init(true, new AEADParameters(new KeyParameter(key), 33, randomBytes(12)));
                fail(msg(c, "bad MAC size accepted"));
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }

            assertNothingProcessed(c);

            // a good init recovers it.
            byte[] fresh = randomBytes(12);
            assertTrue(msg(c, "recovery"), Arrays.areEqual(
                encrypt(new GCMBlockCipher(new AESEngine()), new AEADParameters(new KeyParameter(key), 128, fresh, aad), p2),
                encrypt(c, new AEADParameters(new KeyParameter(key), 128, fresh, aad), p2)));
        }
    }

    /**
     * After doFinal, encryption under the same nonce is over: no more data or AAD is taken, and
     * nothing is written.
     */
    public void testNoProcessingAfterFinalisedEncryption()
        throws Exception
    {
        GCMModeCipher[] cs = ciphers();
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            encrypt(c, new AEADParameters(new KeyParameter(key), 128, nonce, aad), p1);
            assertNothingProcessed(c);

            c.reset();
            assertNothingProcessed(c);
        }
    }

    /**
     * Keystream used, by a byte or by a block, makes a following reset final too, even though no
     * tag was produced.
     */
    public void testResetAfterKeystreamUseRefuses()
        throws Exception
    {
        int[] lens = {1, 15, 16, 17, 64};
        for (int l = 0; l != lens.length; l++)
        {
            GCMModeCipher[] cs = ciphers();
            for (int i = 0; i != cs.length; i++)
            {
                GCMModeCipher c = cs[i];
                c.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
                byte[] out = new byte[lens[l] + 16];
                c.processBytes(randomBytes(lens[l]), 0, lens[l], out, 0);
                c.reset();
                assertNothingProcessed(c);
            }

            cs = ciphers();
            for (int i = 0; i != cs.length; i++)
            {
                GCMModeCipher c = cs[i];
                c.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
                c.processByte((byte)lens[l], new byte[16], 0);
                c.reset();
                assertNothingProcessed(c);
            }
        }
    }

    /**
     * A reset before any keystream has been used, with AAD only or nothing at all, leaves the
     * cipher usable: the result is that of a fresh init, initial AAD included.
     */
    public void testResetBeforeKeystreamUseKeepsCipherUsable()
        throws Exception
    {
        byte[] initialAad = randomBytes(1 + random.nextInt(40));
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, nonce, initialAad);

        GCMModeCipher ref = new GCMBlockCipher(new AESEngine());
        ref.init(true, params);
        ref.processAADBytes(aad, 0, aad.length);
        byte[] expected = new byte[ref.getOutputSize(p1.length)];
        int len = ref.processBytes(p1, 0, p1.length, expected, 0);
        ref.doFinal(expected, len);

        GCMModeCipher[] cs = ciphers();
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            c.init(true, params);
            c.processAADBytes(randomBytes(33), 0, 33);
            c.processBytes(p1, 0, 0, new byte[16], 0);
            c.reset();
            c.reset();

            c.processAADBytes(aad, 0, aad.length);
            byte[] out = new byte[c.getOutputSize(p1.length)];
            len = c.processBytes(p1, 0, p1.length, out, 0);
            c.doFinal(out, len);
            assertTrue(msg(c, "ciphertext after reset"), Arrays.areEqual(expected, out));

            assertNothingProcessed(c);
        }
    }

    /**
     * Decryption is not guarded: it can be reset and repeated, and a same-nonce decrypt init does
     * not reopen encryption under that nonce.
     */
    public void testDecryptionUnaffected()
        throws Exception
    {
        AEADParameters params = new AEADParameters(new KeyParameter(key), 128, nonce, aad);
        byte[] ct = encrypt(new GCMBlockCipher(new AESEngine()), params, p1);

        GCMModeCipher[] cs = ciphers();
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            encrypt(c, params, p2);

            c.init(false, params);
            for (int round = 0; round != 3; round++)
            {
                byte[] pt = new byte[c.getOutputSize(ct.length)];
                int len = c.processBytes(ct, 0, ct.length, pt, 0);
                c.doFinal(pt, len);
                assertTrue(msg(c, "decrypt round " + round), Arrays.areEqual(p1, pt));
                c.reset();
            }

            try
            {
                c.init(true, params);
                fail(msg(c, "nonce reuse accepted after decryption"));
            }
            catch (IllegalArgumentException e)
            {
                assertEquals(msg(c, "message"), "cannot reuse nonce for GCM encryption", e.getMessage());
            }
            assertNothingProcessed(c);
        }
    }

    private byte[] encrypt(GCMModeCipher c, CipherParameters params, byte[] p)
        throws Exception
    {
        c.init(true, params);
        byte[] out = new byte[c.getOutputSize(p.length)];
        int len = c.processBytes(p, 0, p.length, out, 0);
        c.doFinal(out, len);
        return out;
    }

    private void assertNothingProcessed(GCMModeCipher c)
    {
        byte[] out = new byte[p2.length + 32];

        try
        {
            c.processBytes(p2, 0, p2.length, out, 0);
            fail(msg(c, "processBytes accepted"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            c.processByte(p2[0], out, 0);
            fail(msg(c, "processByte accepted"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            c.processAADBytes(p2, 0, p2.length);
            fail(msg(c, "processAADBytes accepted"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            c.processAADByte(p2[0]);
            fail(msg(c, "processAADByte accepted"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            c.doFinal(out, 0);
            fail(msg(c, "doFinal accepted"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        catch (Exception e)
        {
            fail(msg(c, "doFinal: " + e));
        }

        assertTrue(msg(c, "output written"), Arrays.areAllZeroes(out, 0, out.length));
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }
}
