package org.bouncycastle.crypto.test;

import java.lang.reflect.Field;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.drbg.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.HMacSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The AES and DES engine key schedules and the SP 800-90A DRBG working state are held in working
 * buffers that zeroize them: a key schedule as soon as the engine is re-keyed, and both once their
 * owner is no longer referenced and has been collected (finalize() on the base class path, a
 * java.lang.ref.Cleaner from the jdk1.9 multi-release overlay on later JVMs).
 * <p>
 * The key material is taken by reflection and held here without its owner, so only the owner's
 * collection can zeroize it. Collection is requested until that happens or the wait runs out.
 */
public class WorkingBufferZeroizeTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    public String getName()
    {
        return "WorkingBufferZeroize";
    }

    public void performTest()
        throws Exception
    {
        checkEngine("AESEngine", new AESEngine(), "workingKey", 32);
        checkEngine("AESLightEngine", new AESLightEngine(), "WorkingKey", 16);
        checkEngine("DESEngine", new DESEngine(), "workingKey", 8);
        checkEngine("DESedeEngine", new DESedeEngine(), "workingKey2", 24);

        checkDRBG("CTRSP800DRBG", new CTRSP800DRBG(new AESEngine(), 256, 256, entropy(), null, nonce()), "_Key");
        checkDRBG("HashSP800DRBG", new HashSP800DRBG(new SHA256Digest(), 256, entropy(), null, nonce()), "_V");
        checkDRBG("HMacSP800DRBG", new HMacSP800DRBG(new HMac(new SHA256Digest()), 256, entropy(), null, nonce()), "_K");
    }

    private void checkEngine(String label, BlockCipher engine, String fieldName, int keyLen)
        throws Exception
    {
        engine.init(true, new KeyParameter(randomBytes(keyLen)));
        Object first = field(engine, fieldName);
        isTrue(label + " key schedule empty after init", !isZero(first));

        // re-keying zeroizes the previous schedule straight away
        engine.init(true, new KeyParameter(randomBytes(keyLen)));
        isTrue(label + " previous key schedule not zeroized on re-keying", isZero(first));

        Object second = field(engine, fieldName);
        isTrue(label + " key schedule empty after re-keying", !isZero(second));

        engine = null;
        isTrue(label + " key schedule not zeroized after the engine was collected", awaitZero(second));
    }

    private void checkDRBG(String label, SP80090DRBG drbg, String fieldName)
        throws Exception
    {
        drbg.generate(new byte[32], null, false);

        Object state = field(field(drbg, "workingBuf"), fieldName);
        isTrue(label + " working state empty", !isZero(state));

        drbg = null;
        isTrue(label + " working state not zeroized after the DRBG was collected", awaitZero(state));
    }

    private static boolean awaitZero(Object keyMaterial)
        throws InterruptedException
    {
        for (int i = 0; i != 400; i++)
        {
            System.gc();
            System.runFinalization();
            if (isZero(keyMaterial))
            {
                return true;
            }
            Thread.sleep(50);
        }
        return isZero(keyMaterial);
    }

    private static boolean isZero(Object keyMaterial)
    {
        if (keyMaterial instanceof byte[])
        {
            byte[] b = (byte[])keyMaterial;
            for (int i = 0; i != b.length; i++)
            {
                if (b[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }
        if (keyMaterial instanceof int[])
        {
            int[] a = (int[])keyMaterial;
            for (int i = 0; i != a.length; i++)
            {
                if (a[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }
        int[][] rows = (int[][])keyMaterial;
        for (int i = 0; i != rows.length; i++)
        {
            if (rows[i] != null && !isZero(rows[i]))
            {
                return false;
            }
        }
        return true;
    }

    private static Object field(Object owner, String name)
        throws Exception
    {
        Field f = owner.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(owner);
    }

    private static EntropySource entropy()
    {
        return new EntropySource()
        {
            public boolean isPredictionResistant()
            {
                return false;
            }

            public byte[] getEntropy()
            {
                return randomBytes(64);
            }

            public int entropySize()
            {
                return 512;
            }
        };
    }

    private static byte[] nonce()
    {
        return randomBytes(16);
    }

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    public static void main(String[] args)
    {
        runTest(new WorkingBufferZeroizeTest());
    }
}
