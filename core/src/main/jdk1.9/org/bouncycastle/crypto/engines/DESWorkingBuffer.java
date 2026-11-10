package org.bouncycastle.crypto.engines;

import java.lang.ref.Cleaner;

/**
 * Holder for a DES key schedule which zeroizes it when no longer referenced. This later-JVM version uses a
 * {@link Cleaner} instead of {@code finalize()}.
 * <p>
 * The cleanup action must not capture a reference back to this holder (that would make it
 * permanently reachable and the Cleaner would never run), so the key material is handed to a
 * standalone action which is the sole owner of the reference once this holder is collected.
 * </p>
 */
final class DESWorkingBuffer
{
    private static final Cleaner CLEANER = Cleaner.create();

    final int[] workingKey;

    private final Cleaner.Cleanable cleanable;

    DESWorkingBuffer(int[] workingKey)
    {
        this.workingKey = workingKey;
        this.cleanable = CLEANER.register(this, new Zeroizer(workingKey));
    }

    /**
     * Zeroize the key schedule now and remove the Cleaner registration (used when the engine is re-keyed).
     */
    void dispose()
    {
        cleanable.clean();
    }

    static void zeroize(int[] workingKey)
    {
        for (int i = 0; i != workingKey.length; i++)
        {
            workingKey[i] = 0;
        }
    }

    private static final class Zeroizer
        implements Runnable
    {
        private final int[] workingKey;

        Zeroizer(int[] workingKey)
        {
            this.workingKey = workingKey;
        }

        public void run()
        {
            zeroize(workingKey);
        }
    }
}
