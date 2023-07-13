package org.bouncycastle.crypto.engines;


import java.security.DigestException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

/**
 * StreamingFixedSecureRandom uses SHA256 to generate a notionally random stream of good enough entropy
 * to generate prime numbers from that are repeatable.
 * -- Do not use this in production. Do not copy this and use it as an example. --
 */
public class StreamingFixedSecureRandom
    extends SecureRandom
{
    private static java.math.BigInteger REGULAR = new java.math.BigInteger("01020304ffffffff0506070811111111", 16);
    private static java.math.BigInteger ANDROID = new java.math.BigInteger("1111111105060708ffffffff01020304", 16);
    private static java.math.BigInteger CLASSPATH = new java.math.BigInteger("3020104ffffffff05060708111111", 16);

    private static final boolean isAndroidStyle;
    private static final boolean isClasspathStyle;
    private static final boolean isRegularStyle;

    static
    {
        java.math.BigInteger check1 = new java.math.BigInteger(128, new StreamingFixedSecureRandom.RandomChecker());
        java.math.BigInteger check2 = new java.math.BigInteger(120, new StreamingFixedSecureRandom.RandomChecker());

        isAndroidStyle = check1.equals(ANDROID);
        isRegularStyle = check1.equals(REGULAR);
        isClasspathStyle = check2.equals(CLASSPATH);
    }

    private final MessageDigest md;
    private byte[] buf = new byte[32];
    private int ptr = 0;

    /**
     * Creates a new notionally random streaming secure random that is repeatable.
     * DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
     *
     * @param seed
     */
    public StreamingFixedSecureRandom(byte[] seed)
    {
        //
        // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
        //
        try
        {
            //
            // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
            //
            md = MessageDigest.getInstance("SHA-256");
            md.update(seed);
            roll();

        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private void roll()
    {
        //
        // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
        //
        md.update(buf);
        try
        {
            //
            // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
            //
            md.digest(buf, 0, buf.length);
            ptr = 0;
        }
        catch (DigestException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private void load(byte[] dest)
    {
        //
        // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
        //
        int l = dest.length;
        int wp =0;

        while (l > 0)
        {
            if (ptr >= buf.length)
            {
                roll();
            }

            //
            // DO NOT USE THIS IN PRODUCTION, FOR REPEATABILITY IN TESTING ONLY.
            //
            int rem = buf.length - ptr;
            int toCopy = Math.min(rem, l);
            System.arraycopy(buf, ptr, dest, wp, toCopy);
            ptr += toCopy;
            l -= toCopy;
            wp+=toCopy;
        }

    }


    public void nextBytes(byte[] bytes)
    {
        load(bytes);
    }

    public byte[] generateSeed(int numBytes)
    {
        byte[] bytes = new byte[numBytes];

        this.nextBytes(bytes);

        return bytes;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public int nextInt()
    {
        int val = 0;

        val |= nextValue() << 24;
        val |= nextValue() << 16;
        val |= nextValue() << 8;
        val |= nextValue();

        return val;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public long nextLong()
    {
        long val = 0;

        val |= (long)nextValue() << 56;
        val |= (long)nextValue() << 48;
        val |= (long)nextValue() << 40;
        val |= (long)nextValue() << 32;
        val |= (long)nextValue() << 24;
        val |= (long)nextValue() << 16;
        val |= (long)nextValue() << 8;
        val |= (long)nextValue();

        return val;
    }


    private int nextValue()
    {
        if (ptr <= buf.length)
        {
            md.update(buf);
            md.digest(buf);
            ptr = 0;
        }
        return buf[ptr++] & 0xff;
    }

    private static class RandomChecker
        extends SecureRandom
    {
        RandomChecker()
        {
            super(null, new StreamingFixedSecureRandom.DummyProvider());       // to prevent recursion in provider creation
        }

        byte[] data = Hex.decode("01020304ffffffff0506070811111111");
        int index = 0;

        public void nextBytes(byte[] bytes)
        {
            System.arraycopy(data, index, bytes, 0, bytes.length);

            index += bytes.length;
        }
    }

    private static byte[] expandToBitLength(int bitLength, byte[] v)
    {
        if ((bitLength + 7) / 8 > v.length)
        {
            byte[] tmp = new byte[(bitLength + 7) / 8];
            System.arraycopy(v, 0, tmp, tmp.length - v.length, v.length);
            if (isAndroidStyle)
            {
                if (bitLength % 32 != 0)
                {
                    tmp = new byte[((bitLength + 31) / 32) * 4];
                    System.arraycopy(v, 0, tmp, tmp.length - v.length, v.length);

                    int i = Pack.bigEndianToInt(tmp, 0);
                    Pack.intToBigEndian(i << (32 - (bitLength % 32)), tmp, 0);
                }
            }

            return tmp;
        }
        else
        {
            if (isAndroidStyle && bitLength < (v.length * 8))
            {
                if (bitLength % 32 != 0)
                {
                    byte[] tmp = new byte[((bitLength + 31) / 32) * 4];
                    System.arraycopy(v, 0, tmp, tmp.length - v.length, v.length);
                    int i = Pack.bigEndianToInt(tmp, 0);
                    Pack.intToBigEndian(i << (32 - (bitLength % 32)), tmp, 0);

                    return tmp;
                }
            }
        }

        return v;
    }

    private static class DummyProvider
        extends Provider
    {
        DummyProvider()
        {
            super("BCFIPS_STREAMING_FIXED_RNG", 1.0, "BCFIPS Streaming Fixed Secure Random Provider");
        }
    }
}
