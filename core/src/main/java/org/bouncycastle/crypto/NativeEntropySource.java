package org.bouncycastle.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.NativeFeatures;
import org.bouncycastle.util.NativeLoader;


class NativeEntropySource
    implements EntropySource
{

    private final int size;
    private final int effectiveSize;

    private final boolean useSeedSource;

    public NativeEntropySource(int sizeInBits)
    {
        //
        // Round up conversion to bytes.
        //
        size = (sizeInBits + 7) / 8;

        if (!hasHardwareEntropy())
        {
            throw new IllegalStateException("no hardware support for random");
        }

        useSeedSource = NativeLoader.hasHardwareESSeed();

        int mod = modulus();
        effectiveSize = ((size + mod - 1) / mod) * mod;
    }


    public native boolean isPredictionResistant();

    public native int modulus();

    public byte[] getEntropy()
    {
        byte[] buf = new byte[effectiveSize];
        seedBuffer(buf, useSeedSource);

        if (areAllZeroes(buf, 0, buf.length))
        {
            throw new IllegalStateException("entropy source returned an array of len "
                + buf.length + " where all elements are 0");
        }

        if (size != effectiveSize)
        {
            return Arrays.copyOfRange(buf, 0, size);
        }

        return buf;
    }

    private native void seedBuffer(byte[] buf, boolean useSeedSource);


    public int entropySize()
    {
        return size * 8;
    }

    public boolean areAllZeroes(byte[] buf, int off, int len)
    {
        int bits = 0;
        for (int i = 0; i < len; ++i)
        {
            bits |= buf[off + i];
        }
        return bits == 0;
    }


    /**
     * Entropy generation is supported either via rand or specific seed generation at a hardware level.
     *
     * @return true if seed or rand is supported
     */
    static boolean hasHardwareEntropy()
    {
        return NativeLoader.hasHardwareESSeed() || NativeLoader.hasHardwareESRand();
    }


}
