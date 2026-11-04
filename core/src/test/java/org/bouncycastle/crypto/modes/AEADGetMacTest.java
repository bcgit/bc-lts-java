package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * getMac() after each message, on the java GCM and GCM-SIV and on the default ones (native where the
 * native layer is loaded); both must give the same answers.
 * <p>
 * The native GCM and GCM-SIV kept the MAC of the first message processed after an init, and
 * returned it for every later message until the next init. The native GCM also went on returning
 * it after reset(), where the java GCM returns zeros.
 * </p>
 */
public class AEADGetMacTest
    extends TestCase
{
    private static final long SEED = new SecureRandom().nextLong();

    private Random random;
    private byte[] key;
    private byte[] nonce;
    private byte[] aad;

    public void setUp()
    {
        // seeded so a failing run can be reproduced from the seed in the message.
        random = new Random(SEED);

        key = randomBytes(16 + 8 * random.nextInt(3));
        nonce = randomBytes(12);
        aad = randomBytes(random.nextInt(40));
    }

    /**
     * GCM: two messages decrypted after one init, then a reset. A failed decryption in between
     * must not change what getMac() returns for the next good one.
     */
    public void testGCMDecryptGetMac()
        throws Exception
    {
        byte[][] pts = {randomBytes(random.nextInt(100)), randomBytes(1 + random.nextInt(100)), randomBytes(random.nextInt(100))};
        byte[][] cts = new byte[pts.length][];
        for (int m = 0; m != pts.length; m++)
        {
            // separate inits: the same nonce must not be used twice by one encryptor.
            GCMModeCipher enc = new GCMBlockCipher(new AESEngine());
            enc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            cts[m] = run(enc, pts[m]);
        }
        assertFalse("seed " + SEED, Arrays.areEqual(tag(cts[0]), tag(cts[1])));

        GCMModeCipher[] cs = gcmCiphers();
        byte[][] afterReset = new byte[cs.length][];
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            c.init(false, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            for (int m = 0; m != 2; m++)
            {
                assertTrue(msg(c, "decrypt " + m), Arrays.areEqual(pts[m], run(c, cts[m])));
                assertEquals(msg(c, "getMac " + m), Hex.toHexString(tag(cts[m])), Hex.toHexString(c.getMac()));
            }

            byte[] bad = Arrays.clone(cts[2]);
            bad[bad.length - 1] ^= 1;
            try
            {
                run(c, bad);
                fail(msg(c, "tampered tag accepted"));
            }
            catch (InvalidCipherTextException e)
            {
                c.reset();
            }
            assertTrue(msg(c, "decrypt 2"), Arrays.areEqual(pts[2], run(c, cts[2])));
            assertEquals(msg(c, "getMac 2"), Hex.toHexString(tag(cts[2])), Hex.toHexString(c.getMac()));

            c.reset();
            afterReset[i] = c.getMac();
            assertFalse(msg(c, "getMac after reset kept the last MAC"), Arrays.areEqual(tag(cts[2]), afterReset[i]));
        }
        assertEquals("getMac after reset (seed " + SEED + ")", Hex.toHexString(afterReset[0]), Hex.toHexString(afterReset[1]));
    }

    /**
     * GCM: one message encrypted, then a reset, which leaves the cipher needing a new nonce.
     */
    public void testGCMEncryptGetMac()
        throws Exception
    {
        byte[] pt = randomBytes(random.nextInt(100));

        GCMModeCipher[] cs = gcmCiphers();
        byte[][] afterReset = new byte[cs.length][];
        byte[] first = null;
        for (int i = 0; i != cs.length; i++)
        {
            GCMModeCipher c = cs[i];
            c.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            byte[] ct = run(c, pt);
            assertEquals(msg(c, "getMac"), Hex.toHexString(tag(ct)), Hex.toHexString(c.getMac()));
            if (first == null)
            {
                first = ct;
            }
            assertTrue(msg(c, "ciphertext"), Arrays.areEqual(first, ct));

            c.reset();
            afterReset[i] = c.getMac();
            assertFalse(msg(c, "getMac after reset kept the last MAC"), Arrays.areEqual(tag(ct), afterReset[i]));
        }
        assertEquals("getMac after reset (seed " + SEED + ")", Hex.toHexString(afterReset[0]), Hex.toHexString(afterReset[1]));
    }

    /**
     * GCM-SIV: two messages after one init, in each direction. GCM-SIV allows a nonce to be used
     * again, and its getMac() still returns the last MAC after a reset.
     */
    public void testGCMSIVGetMac()
        throws Exception
    {
        // GCM-SIV takes 128 and 256 bit keys only.
        byte[] key = randomBytes(random.nextBoolean() ? 16 : 32);
        byte[][] pts = {randomBytes(random.nextInt(100)), randomBytes(1 + random.nextInt(100))};
        byte[][] cts = new byte[pts.length][];
        GCMSIVModeCipher enc = new GCMSIVBlockCipher(new AESEngine());
        enc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        for (int m = 0; m != pts.length; m++)
        {
            cts[m] = run(enc, pts[m]);
        }
        assertFalse("seed " + SEED, Arrays.areEqual(tag(cts[0]), tag(cts[1])));

        for (int dir = 0; dir != 2; dir++)
        {
            boolean forEncryption = dir == 0;
            GCMSIVModeCipher[] cs = gcmSivCiphers();
            for (int i = 0; i != cs.length; i++)
            {
                GCMSIVModeCipher c = cs[i];
                c.init(forEncryption, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
                for (int m = 0; m != 2; m++)
                {
                    byte[] out = run(c, forEncryption ? pts[m] : cts[m]);
                    assertTrue(msg(c, forEncryption + " message " + m), Arrays.areEqual(forEncryption ? cts[m] : pts[m], out));
                    assertEquals(msg(c, forEncryption + " getMac " + m), Hex.toHexString(tag(cts[m])), Hex.toHexString(c.getMac()));
                }

                c.reset();
                assertEquals(msg(c, forEncryption + " getMac after reset"), Hex.toHexString(tag(cts[1])), Hex.toHexString(c.getMac()));
            }
        }
    }

    private GCMModeCipher[] gcmCiphers()
    {
        return new GCMModeCipher[]{
            new GCMBlockCipher(new AESEngine()),
            GCMBlockCipher.newInstance(AESEngine.newInstance())
        };
    }

    private GCMSIVModeCipher[] gcmSivCiphers()
    {
        return new GCMSIVModeCipher[]{
            new GCMSIVBlockCipher(new AESEngine()),
            GCMSIVBlockCipher.newInstance(AESEngine.newInstance())
        };
    }

    /**
     * Process the whole input in random chunks, then doFinal.
     */
    private byte[] run(AEADBlockCipher c, byte[] in)
        throws InvalidCipherTextException
    {
        byte[] out = new byte[c.getOutputSize(in.length)];
        int inOff = 0, outOff = 0;
        while (inOff < in.length)
        {
            int len = 1 + random.nextInt(in.length - inOff);
            outOff += c.processBytes(in, inOff, len, out, outOff);
            inOff += len;
        }
        outOff += c.doFinal(out, outOff);
        return Arrays.copyOf(out, outOff);
    }

    private static byte[] tag(byte[] ct)
    {
        return Arrays.copyOfRange(ct, ct.length - 16, ct.length);
    }

    private String msg(Object c, String what)
    {
        return c + ": " + what + " (seed " + SEED + ")";
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }
}
