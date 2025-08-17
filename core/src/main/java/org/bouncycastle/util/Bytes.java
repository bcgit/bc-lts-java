package org.bouncycastle.util;

/**
 * Utility methods and constants for bytes.
 */
public class Bytes
{
    public static final int BYTES = 1;
    public static final int SIZE = Byte.SIZE;

    public static void xor(int len, byte[] x, byte[] y, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] = (byte)(x[i] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, int xOff, byte[] y, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[xOff++] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]);
        }
    }

    public static void xor(int len, byte[] x, byte[] y, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[i] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, byte[] y, int yOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[i] ^ y[yOff++]);
        }
    }


    /**
     * Xor x with z0 and save result into both Z0 and Z1
     * z0 = z1 = X xor Z0
     * @param len length
     * @param x
     * @param xOff
     * @param z0
     * @param z0Off
     * @param z1
     * @param z1Off
     */
    public static void xorTee(int len, byte[] x, int xOff, byte[] z0, int z0Off, byte[] z1, int z1Off)
    {
        for (int i = 0; i < len; ++i)
        {
            z0[z0Off+i] = z1[z1Off + i] = (byte)(x[xOff + i] ^ z0[z0Off + i]);
        }
    }

    public static void xorTo(int len, byte[] x, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[i];
        }
    }

    public static void xorTo(int len, byte[] x, int xOff, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[xOff++];
        }
    }

    public static void xorTo(int len, byte[] x, int xOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] ^= x[xOff + i];
        }
    }
}
