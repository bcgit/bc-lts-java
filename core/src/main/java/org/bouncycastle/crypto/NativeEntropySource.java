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
        if (sizeInBits < 1)
        {
            throw new IllegalStateException("bit size less than 1");
        }

        //
        // Round up conversion to bytes.
        //
        size = (sizeInBits + 7) / 8;

        useSeedSource = resolveUseSeedSource();

        int mod = modulus();
        effectiveSize = ((size + mod - 1) / mod) * mod;
    }

    /**
     * Return true where the native entropy source can serve the selected instruction on this
     * machine, reading the selection from the registrar and the features from NativeLoader.
     */
    static boolean isAvailable()
    {
        return isAvailable(DefaultNativeServices.nativeRandSource(),
            NativeLoader.hasNativeService(NativeServices.NRBG),
            NativeLoader.hasNativeService(NativeServices.DRBG));
    }

    /**
     * Return true where the native entropy source can serve source with the features given.
     * <p>
     * Where both features are absent the native layer is off altogether, for example cpu_variant=java
     * or an unsupported platform, and every selection returns false so that the caller can use the
     * SecureRandom fallback. Where the native layer is on but the CPU lacks the forced instruction
     * this throws rather than quietly using the other instruction.
     * </p>
     *
     * @param source  the selected instruction.
     * @param hasSeed true where the CPU has RDSEED.
     * @param hasRand true where the CPU has RDRAND.
     * @return true where the native entropy source can be used.
     */
    static boolean isAvailable(NativeServices.RandSource source, boolean hasSeed, boolean hasRand)
    {
        switch (source)
        {
        case NONE:
            return false;
        case RDSEED:
            if (!hasSeed && hasRand)
            {
                throw new IllegalStateException("RDSEED selected but not supported by this CPU");
            }
            return hasSeed;
        case RDRAND:
            if (!hasRand && hasSeed)
            {
                throw new IllegalStateException("RDRAND selected but not supported by this CPU");
            }
            return hasRand;
        default:
            return hasSeed || hasRand;
        }
    }

    /**
     * Return the useSeedSource flag for seedBuffer, reading the selection from the registrar and
     * the features from NativeLoader.
     */
    static boolean resolveUseSeedSource()
    {
        return resolveUseSeedSource(DefaultNativeServices.nativeRandSource(),
            NativeLoader.hasNativeService(NativeServices.NRBG),
            NativeLoader.hasNativeService(NativeServices.DRBG));
    }

    /**
     * Return the useSeedSource flag for seedBuffer, true for RDSEED and false for RDRAND.
     *
     * @param source  the selected instruction.
     * @param hasSeed true where the CPU has RDSEED.
     * @param hasRand true where the CPU has RDRAND.
     * @return true to use RDSEED, false to use RDRAND.
     * @throws IllegalStateException where the selection cannot be served on this machine.
     */
    static boolean resolveUseSeedSource(NativeServices.RandSource source, boolean hasSeed, boolean hasRand)
    {
        switch (source)
        {
        case NONE:
            throw new IllegalStateException("native entropy source disabled by org.bouncycastle.native.rand=NONE");
        case RDSEED:
            if (!hasSeed)
            {
                throw new IllegalStateException("RDSEED selected but not supported by this CPU");
            }
            return true;
        case RDRAND:
            if (!hasRand)
            {
                throw new IllegalStateException("RDRAND selected but not supported by this CPU");
            }
            return false;
        default:
            if (!hasSeed && !hasRand)
            {
                throw new IllegalStateException("no hardware support for random");
            }
            return hasSeed;
        }
    }

    /**
     * Return the flag this instance passes to seedBuffer, true for RDSEED and false for RDRAND.
     */
    boolean isUseSeedSource()
    {
        return useSeedSource;
    }

    @Override
    public native boolean isPredictionResistant();

    public native int modulus();

    @Override
    public byte[] getEntropy()
    {
        byte[] buf = new byte[effectiveSize];
        seedBuffer(buf, useSeedSource, DefaultNativeServices.maxRNGRetries());



        if (size != effectiveSize)
        {
            return Arrays.copyOfRange(buf, 0, size);
        }

        return buf;
    }

    /**
     * @param maxRetries how many times the hardware instruction is retried per word before the
     *                   call fails, 0 for indefinite retry. See
     *                   {@link DefaultNativeServices#maxRNGRetries()}.
     */
    native void seedBuffer(byte[] buf, boolean useSeedSource, int maxRetries);

    @Override
    public int entropySize()
    {
        return size * 8;
    }



}
