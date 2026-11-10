package org.bouncycastle.crypto.engines;

/**
 * Holder for the three DESede key schedules (the third may be the first) which zeroizes it when no longer referenced. This base version uses
 * {@code finalize()}; the jdk1.9 multi-release overlay of this class uses a
 * {@link java.lang.ref.Cleaner} instead. Ported from bc-fips 2.1.X.
 */
final class DESedeWorkingBuffer
{
    final int[] workingKey1;
    final int[] workingKey2;
    final int[] workingKey3;

    DESedeWorkingBuffer(int[] workingKey1, int[] workingKey2, int[] workingKey3)
    {
        this.workingKey1 = workingKey1;
        this.workingKey2 = workingKey2;
        this.workingKey3 = workingKey3;
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
        zeroize(workingKey1, workingKey2, workingKey3);
    }

    static void zeroize(int[] workingKey1, int[] workingKey2, int[] workingKey3)
    {
        for (int i = 0; i != workingKey1.length; i++)
        {
            workingKey1[i] = 0;
            workingKey2[i] = 0;
            workingKey3[i] = 0;
        }
    }
}
