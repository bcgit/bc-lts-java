package org.bouncycastle.crypto.engines;

/**
 * Holder for a DES key schedule which zeroizes it when no longer referenced. This base version uses
 * {@code finalize()}; the jdk1.9 multi-release overlay of this class uses a
 * {@link java.lang.ref.Cleaner} instead. Ported from bc-fips 2.1.X.
 */
final class DESWorkingBuffer
{
    final int[] workingKey;

    DESWorkingBuffer(int[] workingKey)
    {
        this.workingKey = workingKey;
    }

    protected void finalize()
        throws Throwable
    {
        try
        {
            dispose();
        }
        finally
        {
            super.finalize();
        }
    }

    /**
     * Zeroize the key schedule now (used when the engine is re-keyed).
     */
    void dispose()
    {
        zeroize(workingKey);
    }

    static void zeroize(int[] workingKey)
    {
        for (int i = 0; i != workingKey.length; i++)
        {
            workingKey[i] = 0;
        }
    }
}
