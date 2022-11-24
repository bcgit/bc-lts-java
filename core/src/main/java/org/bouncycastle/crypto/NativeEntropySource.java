package org.bouncycastle.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.prng.EntropySource;


class NativeEntropySource
        implements EntropySource, NativeService
{

    private final int size;
    private final int effectiveSize;

    private final boolean useNRBGSource;

    public NativeEntropySource(int sizeInBits)
    {
        if (sizeInBits <= 0)
        {
            throw new IllegalArgumentException("bit size less than 1");
        }

        //
        // Round up conversion to bytes.
        //
        size = (sizeInBits + 7) / 8;

        if (!hasHardwareEntropy())
        {
            throw new IllegalStateException("no hardware support for random");
        }

        useNRBGSource = CryptoServicesRegistrar.getNativeServices().hasFeature(NativeServices.NRBG);

        int mod = modulus();
        effectiveSize = ((size + mod - 1) / mod) * mod;
    }


    public native boolean isPredictionResistant();

    public native int modulus();

    public byte[] getEntropy()
    {
        byte[] buf = new byte[effectiveSize];
        seedBuffer(buf, useNRBGSource);

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
        if (CryptoServicesRegistrar.hasNativeServices())
        {
            NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();

            return nativeServices.hasAnyFeature(NativeServices.NRBG, NativeServices.DRBG);
        }

        return false;
    }
}
