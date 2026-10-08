package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicesConstraints;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * A native engine whose init fails must not be left holding a context with no key schedule in
 * it: it must refuse to process data, never produce output under an all-zero schedule. And the
 * native CBC and CFB engines must handle re-initialisation the way CBCBlockCipher and
 * CFBBlockCipher do, so that the result does not depend on the host.
 */
public class NativeInitFailureTest
    extends TestCase
{
    private final long seed = new SecureRandom().nextLong();
    private final Random random = new Random(seed);

    /**
     * A refused init, by an IV the native code rejects, leaves CTR unusable: both on a fresh
     * engine and on one that had a working key.
     */
    public void testCTRFailedInitLeavesEngineUnusable()
    {
        if (!nativeAvailable("CTR"))
        {
            return;
        }

        byte[] key = randomBytes(16);
        byte[] in = randomBytes(64);

        // an IV-only init with no key ever supplied.
        AESNativeCTR ctr = new AESNativeCTR();
        try
        {
            ctr.init(true, new ParametersWithIV(null, randomBytes(16)));
            fail(msg("IV-only init of a fresh engine accepted"));
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("cannot replace iv unless key was previously supplied"));
        }
        assertRefusesToProcess(ctr, in);

        // a keyed engine re-initialised with a new key and an IV that is too long.
        ctr = new AESNativeCTR();
        ctr.init(true, new ParametersWithIV(new KeyParameter(key), randomBytes(16)));
        byte[] out = new byte[in.length];
        ctr.processBytes(in, 0, in.length, out, 0);

        byte[] key2 = randomBytes(16);
        try
        {
            ctr.init(true, new ParametersWithIV(new KeyParameter(key2), randomBytes(17)));
            fail(msg("17 byte IV accepted"));
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        assertRefusesToProcess(ctr, in);

        // and a good init afterwards brings it back.
        byte[] iv = randomBytes(16);
        ctr.init(true, new ParametersWithIV(new KeyParameter(key2), iv));
        out = new byte[in.length];
        ctr.processBytes(in, 0, in.length, out, 0);

        SICBlockCipherHolder java = new SICBlockCipherHolder(key2, iv);
        assertTrue(msg("CTR after recovery"), Arrays.areEqual(java.process(in), out));
    }

    /**
     * An IV-only re-init the native code refuses leaves the existing key and position intact, as
     * a refused init of SICBlockCipher does.
     */
    public void testCTRRefusedIVOnlyReinitKeepsState()
    {
        if (!nativeAvailable("CTR"))
        {
            return;
        }

        byte[] key = randomBytes(16);
        byte[] iv = randomBytes(16);
        byte[] in = randomBytes(96);

        AESNativeCTR ctr = new AESNativeCTR();
        ctr.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[in.length];
        ctr.processBytes(in, 0, 32, out, 0);
        try
        {
            ctr.init(true, new ParametersWithIV(null, randomBytes(17)));
            fail(msg("17 byte IV accepted"));
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        ctr.processBytes(in, 32, in.length - 32, out, 32);

        assertTrue(msg("CTR after refused IV-only init"),
            Arrays.areEqual(new SICBlockCipherHolder(key, iv).process(in), out));
    }

    /**
     * A key refused by the services constraints leaves the native ECB engine unusable, rather than
     * working under an all-zero key schedule.
     */
    public void testECBConstraintRefusalLeavesEngineUnusable()
    {
        if (!nativeAvailable("ECB"))
        {
            return;
        }

        AESNativeEngine engine = new AESNativeEngine();
        byte[] in = randomBytes(16);
        byte[] out = new byte[16];

        engine.init(true, new KeyParameter(randomBytes(16)));
        engine.processBlock(in, 0, out, 0);

        CryptoServicesRegistrar.setServicesConstraints(new CryptoServicesConstraints()
        {
            public void check(CryptoServiceProperties service)
            {
                if (service.bitsOfSecurity() == 192)
                {
                    throw new IllegalStateException("192 bit keys refused by test constraints");
                }
            }
        });
        try
        {
            engine.init(true, new KeyParameter(randomBytes(24)));
            fail(msg("constraint not applied"));
        }
        catch (IllegalStateException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("refused by test constraints"));
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
        }

        try
        {
            engine.processBlock(in, 0, out, 0);
            fail(msg("engine processed a block after a refused init"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    /**
     * CBC: a key-only or null init resets the IV to zero, as CBCBlockCipher does.
     */
    public void testCBCReinitMatchesJava()
        throws Exception
    {
        if (!nativeAvailable("CBC"))
        {
            return;
        }

        for (int keySize = 16; keySize <= 32; keySize += 8)
        {
            byte[] key = randomBytes(keySize);
            byte[] key2 = randomBytes(keySize);

            CBCModeCipher nat = new AESNativeCBC();
            CBCModeCipher java = new CBCBlockCipher(new AESEngine());

            Object[][] sequence = {
                {Boolean.TRUE, new ParametersWithIV(new KeyParameter(key), randomBytes(16))},
                {Boolean.TRUE, new KeyParameter(key2)},
                {Boolean.TRUE, new ParametersWithIV(new KeyParameter(key), randomBytes(16))},
                {Boolean.TRUE, null},
                {Boolean.TRUE, new ParametersWithIV(null, randomBytes(16))},
                {Boolean.FALSE, new KeyParameter(key)},
                {Boolean.FALSE, null},
                {Boolean.FALSE, new ParametersWithIV(new KeyParameter(key2), randomBytes(16))},
                {Boolean.FALSE, new KeyParameter(key2)},
            };

            for (int i = 0; i != sequence.length; i++)
            {
                boolean forEncryption = ((Boolean)sequence[i][0]).booleanValue();
                org.bouncycastle.crypto.CipherParameters params = (org.bouncycastle.crypto.CipherParameters)sequence[i][1];
                nat.init(forEncryption, params);
                java.init(forEncryption, params);

                byte[] in = randomBytes(16 * (1 + random.nextInt(8)));
                assertTrue(msg("CBC step " + i + ", key size " + keySize),
                    Arrays.areEqual(cbc(java, in), cbc(nat, in)));
            }
        }
    }

    /**
     * CFB: a key-only init on a fresh engine uses a zero IV, a null init reuses key and IV, the
     * direction may change without a new key, and an IV set before any key is kept, all as
     * CFBBlockCipher does.
     */
    public void testCFBReinitMatchesJava()
        throws Exception
    {
        if (!nativeAvailable("CFB"))
        {
            return;
        }

        for (int keySize = 16; keySize <= 32; keySize += 8)
        {
            byte[] key = randomBytes(keySize);
            byte[] key2 = randomBytes(keySize);

            // a fresh engine given only a key.
            compareCFB(keySize, new Object[][]{
                {Boolean.TRUE, new KeyParameter(key)},
                {Boolean.TRUE, null},
                {Boolean.FALSE, null},
                {Boolean.TRUE, new ParametersWithIV(null, randomBytes(16))},
                {Boolean.FALSE, new KeyParameter(key2)},
                {Boolean.TRUE, new ParametersWithIV(new KeyParameter(key), randomBytes(1 + random.nextInt(16)))},
                {Boolean.FALSE, new KeyParameter(key2)},
                {Boolean.FALSE, new ParametersWithIV(null, randomBytes(16))},
                {Boolean.TRUE, null},
            });

            // a fresh engine given an IV before any key.
            compareCFB(keySize, new Object[][]{
                {Boolean.TRUE, new ParametersWithIV(null, randomBytes(16))},
                {Boolean.TRUE, new KeyParameter(key)},
                {Boolean.FALSE, null},
            });
        }
    }

    /**
     * CFB with no key ever supplied refuses to process data, as CFBBlockCipher does.
     */
    public void testCFBWithoutKeyRefusesToProcess()
    {
        if (!nativeAvailable("CFB"))
        {
            return;
        }

        AESNativeCFB cfb = new AESNativeCFB(128);
        cfb.init(true, new ParametersWithIV(null, randomBytes(16)));
        cfb.init(false, null);
        byte[] in = randomBytes(32);
        try
        {
            cfb.processBytes(in, 0, in.length, new byte[in.length], 0);
            fail(msg("CFB processed data with no key"));
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    /**
     * The native code clears its copy of a key before releasing it. It must not copy that cleared
     * copy back: the caller's key array, which these engines hand to the native code directly,
     * must come back unchanged, and the key must still have been used.
     */
    public void testNativeInitLeavesCallerKeyIntact()
        throws Exception
    {
        for (int keySize = 16; keySize <= 32; keySize += 8)
        {
            byte[] key = randomBytes(keySize);
            key[0] |= 1;
            byte[] keyCopy = Arrays.clone(key);
            byte[] in = randomBytes(64);

            if (nativeAvailable("ECB"))
            {
                AESNativeEngine nat = new AESNativeEngine();
                nat.init(true, new KeyParameter(key));
                assertTrue(msg("ECB init changed the caller's key"), Arrays.areEqual(keyCopy, key));

                AESEngine java = new AESEngine();
                java.init(true, new KeyParameter(keyCopy));
                byte[] natOut = new byte[16];
                byte[] javaOut = new byte[16];
                nat.processBlock(in, 0, natOut, 0);
                java.processBlock(in, 0, javaOut, 0);
                assertTrue(msg("ECB, key size " + keySize), Arrays.areEqual(javaOut, natOut));
            }

            if (CryptoServicesRegistrar.hasEnabledService(org.bouncycastle.crypto.NativeServices.AES_CBC_PC))
            {
                ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), randomBytes(16));
                org.bouncycastle.crypto.modes.AESCBCModePacketCipher nat =
                    org.bouncycastle.crypto.modes.AESCBCPacketCipher.newInstance();
                byte[] natOut = new byte[in.length];
                nat.processPacket(true, params, in, 0, in.length, natOut, 0);
                assertTrue(msg("CBC packet cipher changed the caller's key"), Arrays.areEqual(keyCopy, key));

                byte[] javaOut = new byte[in.length];
                new org.bouncycastle.crypto.modes.AESCBCPacketCipher().processPacket(true,
                    new ParametersWithIV(new KeyParameter(keyCopy), params.getIV()), in, 0, in.length, javaOut, 0);
                assertTrue(msg("CBC packet cipher, key size " + keySize), Arrays.areEqual(javaOut, natOut));
            }
        }
    }

    private void compareCFB(int keySize, Object[][] sequence)
    {
        CFBModeCipher nat = new AESNativeCFB(128);
        CFBModeCipher java = new CFBBlockCipher(new AESEngine(), 128);

        for (int i = 0; i != sequence.length; i++)
        {
            boolean forEncryption = ((Boolean)sequence[i][0]).booleanValue();
            org.bouncycastle.crypto.CipherParameters params = (org.bouncycastle.crypto.CipherParameters)sequence[i][1];
            nat.init(forEncryption, params);
            java.init(forEncryption, params);

            byte[] in = randomBytes(1 + random.nextInt(100));
            byte[] natOut = new byte[in.length];
            byte[] javaOut = new byte[in.length];
            try
            {
                java.processBytes(in, 0, in.length, javaOut, 0);
            }
            catch (IllegalStateException e)
            {
                // no key yet: the native engine must refuse as well.
                try
                {
                    nat.processBytes(in, 0, in.length, natOut, 0);
                    fail(msg("CFB step " + i + ": native processed data the java engine refused"));
                }
                catch (IllegalStateException expected)
                {
                    continue;
                }
            }
            nat.processBytes(in, 0, in.length, natOut, 0);
            assertTrue(msg("CFB step " + i + ", key size " + keySize), Arrays.areEqual(javaOut, natOut));
        }
    }

    private static byte[] cbc(CBCModeCipher cipher, byte[] in)
    {
        byte[] out = new byte[in.length];
        for (int off = 0; off < in.length; off += 16)
        {
            cipher.processBlock(in, off, out, off);
        }
        return out;
    }

    private void assertRefusesToProcess(AESNativeCTR ctr, byte[] in)
    {
        // a single block, a single byte and a longer run take different paths in the native code.
        int[] lens = {16, 1, in.length};
        for (int i = 0; i != lens.length; i++)
        {
            byte[] out = new byte[lens[i]];
            try
            {
                if (lens[i] == 1)
                {
                    out[0] = ctr.returnByte(in[0]);
                }
                else
                {
                    ctr.processBytes(in, 0, lens[i], out, 0);
                }
                fail(msg("CTR processed " + lens[i] + " bytes after a failed init"));
            }
            catch (IllegalStateException e)
            {
                // expected
            }
            assertTrue(msg("CTR wrote output after a failed init"), Arrays.areAllZeroes(out, 0, out.length));
        }
    }

    private boolean nativeAvailable(String mode)
    {
        if (CryptoServicesRegistrar.getNativeServices().hasService("AES/" + mode))
        {
            return true;
        }
        System.out.println("Skipping native init failure test for AES/" + mode + ": no native support");
        return false;
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    private String msg(String s)
    {
        return s + " (seed " + seed + ")";
    }

    private static class SICBlockCipherHolder
    {
        private final org.bouncycastle.crypto.modes.SICBlockCipher cipher =
            new org.bouncycastle.crypto.modes.SICBlockCipher(new AESEngine());

        SICBlockCipherHolder(byte[] key, byte[] iv)
        {
            cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        }

        byte[] process(byte[] in)
        {
            byte[] out = new byte[in.length];
            cipher.processBytes(in, 0, in.length, out, 0);
            return out;
        }
    }
}
