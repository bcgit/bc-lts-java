package org.bouncycastle.crypto.prng.drbg;

import java.lang.ref.Cleaner;
import java.util.Arrays;

/**
 * Holder for the Hash DRBG working state (V, C), which is reassigned over reseeding, zeroized when the owning DRBG is no longer
 * referenced. This later-JVM version registers a {@link Cleaner} against the owning DRBG; the action
 * reads this holder's current fields when it runs, and never captures the DRBG, so the DRBG stays
 * collectable.
 */
final class HashDRBGWorkingBuffer
{
    private static final Cleaner CLEANER = Cleaner.create();

    byte[] _V;
    byte[] _C;

    void registerCleanup(Object owner)
    {
        CLEANER.register(owner, new Zeroizer(this));
    }

    static void zeroize(HashDRBGWorkingBuffer buf)
    {
        if (buf._V != null)
        {
            Arrays.fill(buf._V, (byte)0);
        }
        if (buf._C != null)
        {
            Arrays.fill(buf._C, (byte)0);
        }
    }

    private static final class Zeroizer
        implements Runnable
    {
        private final HashDRBGWorkingBuffer buf;

        Zeroizer(HashDRBGWorkingBuffer buf)
        {
            this.buf = buf;
        }

        public void run()
        {
            zeroize(buf);
        }
    }
}
