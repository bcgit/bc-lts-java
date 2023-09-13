package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;


/**
 * implementation of SHAKE based on following KeccakNISTInterface.c from https://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHAKEDigest
        extends KeccakDigest
        implements SavableDigestXof
{
    private static int checkBitLength(int bitStrength)
    {
        switch (bitStrength)
        {
            case 128:
            case 256:
                return bitStrength;
            default:
                throw new IllegalArgumentException("'bitStrength' " + bitStrength + " not supported for SHAKE");
        }
    }


    public static SavableDigestXof newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            return new SHAKENativeDigest();
        }
        return new SHAKEDigest();
    }

    public SHAKEDigest()
    {
        this(128);
    }


    public static SavableDigestXof newInstance(CryptoServicePurpose purpose)
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            return new SHAKENativeDigest(purpose);
        }
        return new SHAKEDigest(purpose);
    }

    public SHAKEDigest(CryptoServicePurpose purpose)
    {
        this(128, purpose);
    }


    public static SavableDigestXof newInstance(int bitStrength)
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            return new SHAKENativeDigest(bitStrength);
        }
        return new SHAKEDigest(bitStrength);
    }

    /**
     * Base constructor.
     *
     * @param bitStrength the security strength in bits of the XOF.
     */
    public SHAKEDigest(int bitStrength)
    {
        super(checkBitLength(bitStrength), CryptoServicePurpose.ANY);
    }


    public static SavableDigestXof newInstance(int bitStrength, CryptoServicePurpose purpose)
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            return new SHAKENativeDigest(bitStrength, purpose);
        }
        return new SHAKEDigest(bitStrength, purpose);
    }


    public static SavableDigestXof newInstance(byte[] encoded, CryptoServicePurpose purpose)
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            return new SHAKENativeDigest(encoded, purpose);
        }
        return new SHAKEDigest(encoded, purpose);
    }


    /**
     * Base constructor.
     *
     * @param bitStrength the security strength in bits of the XOF.
     * @param purpose     the purpose of the digest will be used for.
     */
    public SHAKEDigest(int bitStrength, CryptoServicePurpose purpose)
    {
        super(checkBitLength(bitStrength), purpose);
    }

    public static SavableDigestXof newInstance(Digest digest)
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE))
        {
            if (digest instanceof SHAKENativeDigest)
            {
                return new SHAKENativeDigest((SHAKENativeDigest) digest);
            }
        }
        if (digest instanceof SHAKEDigest)
        {
            return new SHAKEDigest((SHAKEDigest) digest);
        }

        throw new IllegalArgumentException("digest must be either SHAKENativeDigest or SHAKEDigest");
    }


    /**
     * Clone constructor
     *
     * @param source the other digest to be copied.
     */
    public SHAKEDigest(SHAKEDigest source)
    {
        super(source);
    }

    public SHAKEDigest(byte[] encoded)
    {
        if (encoded.length != 1 + 12 + (state.length * 8))
        {
            throw new IllegalArgumentException("encoded state has incorrect length");
        }

        bitsInQueue = Pack.bigEndianToInt(encoded, 0);
        rate = Pack.bigEndianToInt(encoded, 4);
        squeezing = Integer.MAX_VALUE == Pack.bigEndianToInt(encoded, 8);
        fixedOutputLength = Pack.bigEndianToInt(encoded, 12);
        int p = 16;
        for (int t = 0; t < state.length; t++)
        {
            state[t] = Pack.bigEndianToInt(encoded, p += 8);
        }
        this.purpose = CryptoServicePurpose.values()[encoded[p]];
    }

    public SHAKEDigest(byte[] encoded, CryptoServicePurpose purpose)
    {
        this(encoded);
        this.purpose = purpose;
    }

    public String getAlgorithmName()
    {
        return "SHAKE" + fixedOutputLength;
    }

    public int getDigestSize()
    {
        return fixedOutputLength / 4;
    }

    public int doFinal(byte[] out, int outOff)
    {
        return doFinal(out, outOff, getDigestSize());
    }

    public int doFinal(byte[] out, int outOff, int outLen)
    {
        int length = doOutput(out, outOff, outLen);

        reset();

        return length;
    }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (!squeezing)
        {
            absorbBits(0x0F, 4);
        }

        squeeze(out, outOff, ((long) outLen) * 8);

        return outLen;
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits)
    {
        return doFinal(out, outOff, getDigestSize(), partialByte, partialBits);
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, int outLen, byte partialByte, int partialBits)
    {
        if (partialBits < 0 || partialBits > 7)
        {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }

        int finalInput = (partialByte & ((1 << partialBits) - 1)) | (0x0F << partialBits);
        int finalBits = partialBits + 4;

        if (finalBits >= 8)
        {
            absorb((byte) finalInput);
            finalBits -= 8;
            finalInput >>>= 8;
        }

        if (finalBits > 0)
        {
            absorbBits(finalInput, finalBits);
        }

        squeeze(out, outOff, ((long) outLen) * 8);

        reset();

        return outLen;
    }

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, purpose);
    }

    @Override
    public String toString()
    {
        return "SHAKE[Java]()";
    }

    @Override
    public byte[] getEncodedState()
    {
        byte[] out = new byte[1 + 12 + (state.length * 8)];
        Pack.intToBigEndian(bitsInQueue, out, 0);
        Pack.intToBigEndian(rate, out, 4);
        Pack.intToBigEndian(squeezing ? Integer.MIN_VALUE : 0, out, 8);
        Pack.intToBigEndian(fixedOutputLength, out, 12);
        int p = 16;
        for (long s : state)
        {
            Pack.longToBigEndian(s, out, p += 8);
        }
        state[state.length - 1] = (byte) purpose.ordinal();
        return out;
    }

    @Override
    public Memoable copy()
    {
        return new SHAKEDigest(this);
    }

    @Override
    public void reset(Memoable other)
    {
        if (!(other instanceof SHAKEDigest))
        {
            throw new IllegalArgumentException("no SHAKEDigest instance");
        }

        this.bitsInQueue = ((SHAKEDigest) other).bitsInQueue;
        this.rate = ((SHAKEDigest) other).rate;
        this.squeezing = ((SHAKEDigest) other).squeezing;
        this.fixedOutputLength = ((SHAKEDigest) other).fixedOutputLength;
        System.arraycopy(((SHAKEDigest) other).state, 0, this.state, 0, this.state.length);
        this.purpose = ((SHAKEDigest) other).purpose;

    }
}
