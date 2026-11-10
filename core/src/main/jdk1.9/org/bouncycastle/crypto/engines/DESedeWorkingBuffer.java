package org.bouncycastle.crypto.engines;

import java.lang.ref.Cleaner;

/**
 * Holder for the three DESede key schedules (the third may be the first) which zeroizes it when no longer referenced. This later-JVM version uses a
 * {@link Cleaner} instead of {@code finalize()}.
 * <p>
 * The cleanup action must not capture a reference back to this holder (that would make it
 * permanently reachable and the Cleaner would never run), so the key material is handed to a
 * standalone action which is the sole owner of the reference once this holder is collected.
 * </p>
 */
final class DESedeWorkingBuffer
{
    private static final Cleaner CLEANER = Cleaner.create();

    final int[] workingKey1;
    final int[] workingKey2;
    final int[] workingKey3;

    private final Cleaner.Cleanable cleanable;

    DESedeWorkingBuffer(int[] workingKey1, int[] workingKey2, int[] workingKey3)
    {
        this.workingKey1 = workingKey1;
        this.workingKey2 = workingKey2;
        this.workingKey3 = workingKey3;
        this.cleanable = CLEANER.register(this, new Zeroizer(workingKey1, workingKey2, workingKey3));
    }

    /**
     * Zeroize the key schedule now and remove the Cleaner registration (used when the engine is re-keyed).
     */
    void dispose()
    {
        cleanable.clean();
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

    private static final class Zeroizer
        implements Runnable
    {
        private final int[] workingKey1;
        private final int[] workingKey2;
        private final int[] workingKey3;

        Zeroizer(int[] workingKey1, int[] workingKey2, int[] workingKey3)
        {
            this.workingKey1 = workingKey1;
            this.workingKey2 = workingKey2;
            this.workingKey3 = workingKey3;
        }

        public void run()
        {
            zeroize(workingKey1, workingKey2, workingKey3);
        }
    }
}
