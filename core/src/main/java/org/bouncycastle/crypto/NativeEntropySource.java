package org.bouncycastle.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.prng.EntropySource;

class NativeEntropySource
    implements EntropySource
{
    /**
     * CPU can generate random values, algorithm depends on CPU.
     * Check CPU Vendor documentation for applicability.
     */
    private static final int HW_RND = 1;
    private static final int HW_SEED = 2;

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

        useSeedSource = hasHardwareESSeed();

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

    private native void seedBuffer(byte[] buf, boolean useSeedSource);

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

    /**
       * Hardware rand is supported.
       *
       * @return true if a hardware rand is supported.
       */
      static boolean hasHardwareESRand()
      {
          return FipsStatus.isNativeSupported() && hasHardwareRand();
      }

      /**
       * Hardware seed generation is supported.
       *
       * @return true is the CPU has specific support for seed generation.
       */
      static boolean hasHardwareESSeed()
      {
          return FipsStatus.isNativeSupported() && hasHardwareSeed();
      }

      /**
       * Entropy generation is supported either via rand or specific seed generation at a hardware level.
       *
       * @return true if seed or rand is supported
       */
      static boolean hasHardwareEntropy()
      {
          return hasHardwareESSeed() || hasHardwareESRand();
      }

      static boolean hasHardwareRand()
      {
          try
          {
              return hasNativeRand();
          }
          catch (UnsatisfiedLinkError ule)
          {
              return false;
          }
      }

    static boolean hasHardwareSeed()
    {
        try
        {
            return hasNativeSeed();
        }
        catch (UnsatisfiedLinkError ule)
        {
            return false;
        }
    }

    private static boolean hasNativeRand()
    {
        return (rngCapabilities() & HW_RND) == HW_RND;
    }

    private static boolean hasNativeSeed()
    {
        return (rngCapabilities() & HW_SEED) == HW_SEED;
    }

    private static native int rngCapabilities();
}
