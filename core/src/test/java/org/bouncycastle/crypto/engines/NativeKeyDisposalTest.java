package org.bouncycastle.crypto.engines;

import java.lang.reflect.Field;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeReference;

/**
 * The native mode wrappers keep a copy of the key, which must be cleared once the native
 * reference holding it is disposed of - and must never be an array the caller, or a later
 * wrapper, is still using.
 */
public class NativeKeyDisposalTest
    extends TestCase
{
    private static final long GC_TIMEOUT_MS = 30000;

    private static final String[] MODES = { "GCM", "CCM", "CBC", "CFB", "CTR", "GCM-SIV" };

    private final SecureRandom random = new SecureRandom();

    public void testKeyClearedOnDisposal()
        throws Exception
    {
        for (int i = 0; i != MODES.length; i++)
        {
            String mode = MODES[i];
            if (!nativeAvailable(mode))
            {
                continue;
            }

            for (int keySize = 16; keySize <= 32; keySize += 8)
            {
                if (keySize == 24 && mode.equals("GCM-SIV"))
                {
                    continue;   // GCM-SIV keys are 16 or 32 bytes only.
                }

                byte[] key = new byte[keySize];
                random.nextBytes(key);
                key[0] |= 1;    // never all zero, so a cleared array can't pass for the original.
                KeyParameter keyParam = new KeyParameter(key);

                byte[] wrapperKey = initAndDrop(mode, keyParam);
                if (wrapperKey == null)
                {
                    // the wrapper for this mode doesn't hold the key (e.g. the pre-Java 9 GCM-SIV).
                    continue;
                }

                waitUntilCleared(mode, wrapperKey);

                // the key the caller handed in must be untouched by the disposal.
                assertTrue(mode + ": caller key cleared", Arrays.areEqual(key, keyParam.getKey()));
            }
        }
    }

    /**
     * Re-initialising with a null key reuses the previous key; the new native reference must hold
     * its own copy, not share the previous one, which is cleared when that is disposed of.
     */
    public void testKeyReuseSurvivesDisposalOfPreviousReference()
        throws Exception
    {
        byte[] key = new byte[16];
        byte[] iv1 = new byte[16];
        byte[] iv2 = new byte[16];
        byte[] msg = new byte[100];
        random.nextBytes(key);
        random.nextBytes(iv1);
        random.nextBytes(iv2);
        random.nextBytes(msg);
        key[0] |= 1;
        iv2[0] = (byte)(iv1[0] ^ 1);

        if (nativeAvailable("GCM"))
        {
            GCMModeCipher nat = new AESNativeGCM();
            nat.init(true, new AEADParameters(new KeyParameter(key), 128, Arrays.copyOf(iv1, 12)));
            byte[] previous = wrapperKey(nat);
            nat.init(true, new AEADParameters(null, 128, Arrays.copyOf(iv2, 12)));
            assertNotSame(previous, wrapperKey(nat));
            waitUntilCleared("GCM", previous);

            GCMModeCipher java = new GCMBlockCipher(new AESEngine());
            java.init(true, new AEADParameters(new KeyParameter(key), 128, Arrays.copyOf(iv2, 12)));
            assertTrue("GCM", Arrays.areEqual(gcm(java, msg), gcm(nat, msg)));
        }

        if (nativeAvailable("CFB"))
        {
            CFBModeCipher nat = new AESNativeCFB(128);
            nat.init(true, new ParametersWithIV(new KeyParameter(key), iv1));
            byte[] previous = wrapperKey(nat);
            nat.init(true, new ParametersWithIV(null, iv2));
            assertNotSame(previous, wrapperKey(nat));
            waitUntilCleared("CFB", previous);

            CFBModeCipher java = new CFBBlockCipher(new AESEngine(), 128);
            java.init(true, new ParametersWithIV(new KeyParameter(key), iv2));
            assertTrue("CFB", Arrays.areEqual(stream(java, msg), stream(nat, msg)));
        }

        if (nativeAvailable("CTR"))
        {
            // a new key replaces the reference; an IV-only change then keeps using the new one.
            byte[] key2 = Arrays.clone(key);
            key2[0] ^= 2;

            CTRModeCipher nat = new AESNativeCTR();
            nat.init(true, new ParametersWithIV(new KeyParameter(key), iv1));
            byte[] previous = wrapperKey(nat);
            nat.init(true, new ParametersWithIV(new KeyParameter(key2), iv1));
            nat.init(true, new ParametersWithIV(null, iv2));
            assertNotSame(previous, wrapperKey(nat));
            waitUntilCleared("CTR", previous);

            CTRModeCipher java = new SICBlockCipher(new AESEngine());
            java.init(true, new ParametersWithIV(new KeyParameter(key2), iv2));
            assertTrue("CTR", Arrays.areEqual(stream(java, msg), stream(nat, msg)));
        }
    }

    private static boolean nativeAvailable(String mode)
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (nativeServices.hasService("AES/" + mode))
        {
            return true;
        }
        System.out.println("Skipping native key disposal test for AES/" + mode + ": no native support");
        return false;
    }

    /**
     * Initialise a native engine for the mode, then let it go. Returns the wrapper's key array,
     * checked to be a copy of the caller's key, or null if the wrapper holds no key.
     */
    private byte[] initAndDrop(String mode, KeyParameter keyParam)
        throws Exception
    {
        Object engine;
        CipherParameters params;
        if (mode.equals("GCM"))
        {
            AESNativeGCM gcm = new AESNativeGCM();
            gcm.init(true, params = new AEADParameters(keyParam, 128, nonce(12)));
            engine = gcm;
        }
        else if (mode.equals("CCM"))
        {
            AESNativeCCM ccm = new AESNativeCCM();
            ccm.init(true, params = new AEADParameters(keyParam, 128, nonce(13)));
            engine = ccm;
        }
        else if (mode.equals("CBC"))
        {
            AESNativeCBC cbc = new AESNativeCBC();
            cbc.init(true, params = new ParametersWithIV(keyParam, nonce(16)));
            engine = cbc;
        }
        else if (mode.equals("CFB"))
        {
            AESNativeCFB cfb = new AESNativeCFB(128);
            cfb.init(true, params = new ParametersWithIV(keyParam, nonce(16)));
            engine = cfb;
        }
        else if (mode.equals("CTR"))
        {
            AESNativeCTR ctr = new AESNativeCTR();
            ctr.init(true, params = new ParametersWithIV(keyParam, nonce(16)));
            engine = ctr;
        }
        else
        {
            AESNativeGCMSIV siv = new AESNativeGCMSIV();
            siv.init(true, params = new AEADParameters(keyParam, 128, nonce(12)));
            engine = siv;
        }

        byte[] wrapperKey = wrapperKey(engine);
        if (wrapperKey != null)
        {
            assertNotSame(mode + ": wrapper shares the caller's key array", keyParam.getKey(), wrapperKey);
            assertTrue(mode + ": wrapper key is not the key", Arrays.areEqual(keyParam.getKey(), wrapperKey));
        }
        return wrapperKey;
    }

    private static void waitUntilCleared(String mode, byte[] wrapperKey)
        throws InterruptedException
    {
        long end = System.currentTimeMillis() + GC_TIMEOUT_MS;
        while (!Arrays.areAllZeroes(wrapperKey, 0, wrapperKey.length))
        {
            if (System.currentTimeMillis() > end)
            {
                fail(mode + ": key not cleared after the native reference was disposed of");
            }
            System.gc();
            Thread.sleep(20);
        }
    }

    /**
     * The key array held by the engine's native reference wrapper, or null if it holds none.
     */
    private static byte[] wrapperKey(Object engine)
        throws IllegalAccessException
    {
        for (Class c = engine.getClass(); c != null; c = c.getSuperclass())
        {
            Field[] fields = c.getDeclaredFields();
            for (int i = 0; i != fields.length; i++)
            {
                if (NativeReference.class.isAssignableFrom(fields[i].getType()))
                {
                    fields[i].setAccessible(true);
                    Object wrapper = fields[i].get(engine);
                    Field[] wrapperFields = wrapper.getClass().getDeclaredFields();
                    for (int j = 0; j != wrapperFields.length; j++)
                    {
                        if (wrapperFields[j].getType() == byte[].class)
                        {
                            wrapperFields[j].setAccessible(true);
                            return (byte[])wrapperFields[j].get(wrapper);
                        }
                    }
                    return null;
                }
            }
        }
        fail("no native reference in " + engine.getClass().getName());
        return null;
    }

    private byte[] nonce(int len)
    {
        byte[] nonce = new byte[len];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] gcm(GCMModeCipher cipher, byte[] in)
        throws Exception
    {
        byte[] out = new byte[cipher.getOutputSize(in.length)];
        int len = cipher.processBytes(in, 0, in.length, out, 0);
        len += cipher.doFinal(out, len);
        return Arrays.copyOfRange(out, 0, len);
    }

    private static byte[] stream(org.bouncycastle.crypto.StreamCipher cipher, byte[] in)
    {
        byte[] out = new byte[in.length];
        cipher.processBytes(in, 0, in.length, out, 0);
        return out;
    }
}
