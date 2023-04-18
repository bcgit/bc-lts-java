package org.bouncycastle.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.prng.EntropySource;


class NativeEntropySource
        implements EntropySource
{
    private final int size;
    private final int effectiveSize;

    private final boolean useSeedSource;

    public NativeEntropySource(int sizeInBits)
    {
        if (sizeInBits <1) {
            throw new IllegalStateException("bit size less than 1");
        }

        //
        // Round up conversion to bytes.
        //
        size = (sizeInBits + 7) / 8;

        if (!NativeLoader.hasNativeService(NativeServices.DRBG) ||
            !NativeLoader.hasNativeService(NativeServices.NRBG))
        {
            throw new IllegalStateException("no hardware support for random");
        }

        useSeedSource = NativeLoader.hasNativeService(NativeServices.NRBG);

        int mod = modulus();
        effectiveSize = ((size + mod - 1) / mod) * mod;
    }

    @Override
    public native boolean isPredictionResistant();

    public native int modulus();

    @Override
    public byte[] getEntropy()
    {
        byte[] buf = new byte[effectiveSize];
        seedBuffer(buf, useSeedSource);

        if (areAllZeroes(buf, 0, buf.length))
        {
            throw new IllegalStateException("entropy source return array of len "
                + buf.length + " where all elements are 0");
        }

        if (size != effectiveSize)
        {
            return Arrays.copyOfRange(buf, 0, size);
        }

        return buf;
    }

    native void seedBuffer(byte[] buf, boolean useSeedSource);

    @Override
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

}

