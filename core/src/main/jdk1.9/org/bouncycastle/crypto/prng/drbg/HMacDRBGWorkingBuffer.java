package org.bouncycastle.crypto.prng.drbg;

import java.lang.ref.Cleaner;
import java.util.Arrays;

/**
 * Holder for the HMAC DRBG working state (K, V), which is reassigned over reseeding, zeroized when the owning DRBG is no longer
 * referenced. This later-JVM version registers a {@link Cleaner} against the owning DRBG; the action
 * reads this holder's current fields when it runs, and never captures the DRBG, so the DRBG stays
 * collectable.
 */
final class HMacDRBGWorkingBuffer
{
    private static final Cleaner CLEANER = Cleaner.create();

    byte[] _K;
    byte[] _V;

    void registerCleanup(Object owner)
    {
        CLEANER.register(owner, new Zeroizer(this));
    }

    static void zeroize(HMacDRBGWorkingBuffer buf)
    {
        if (buf._K != null)
        {
            Arrays.fill(buf._K, (byte)0);
        }
        if (buf._V != null)
        {
            Arrays.fill(buf._V, (byte)0);
        }
    }

    private static final class Zeroizer
        implements Runnable
    {
        private final HMacDRBGWorkingBuffer buf;

        Zeroizer(HMacDRBGWorkingBuffer buf)
        {
            this.buf = buf;
        }

        public void run()
        {
            zeroize(buf);
        }
    }
}
