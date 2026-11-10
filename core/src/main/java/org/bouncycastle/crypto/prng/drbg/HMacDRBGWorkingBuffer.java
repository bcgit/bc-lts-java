package org.bouncycastle.crypto.prng.drbg;

import java.util.Arrays;

/**
 * Holder for the HMAC DRBG working state (K, V), which is reassigned over reseeding, zeroized when the owning DRBG is no longer
 * referenced. This base version uses {@code finalize()}; the jdk1.9 multi-release overlay of this class
 * registers a {@link java.lang.ref.Cleaner} against the owning DRBG instead. Ported from bc-fips 2.1.X.
 */
final class HMacDRBGWorkingBuffer
{
    byte[] _K;
    byte[] _V;

    /**
     * Tie zeroization to the garbage collection of {@code owner} (the DRBG). A no-op in this base
     * version, where {@link #finalize()} performs the zeroization; the overlay registers a Cleaner.
     */
    void registerCleanup(Object owner)
    {
    }

    protected void finalize()
        throws Throwable
    {
        try
        {
            zeroize(this);
        }
        finally
        {
            super.finalize();
        }
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
}
