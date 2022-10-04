package org.bouncycastle.util;

import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Basic 20 byte finger print class.
 */
public class Fingerprint
{
    private static char[] encodingTable =
    {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private final byte[] fingerprint;

    /**
     * Base constructor - use SHAKE-256 (160 bits). This is the recommended one as it is also
     * produced by the FIPS API.
     *
     * @param source original data to calculate the fingerprint from.
     */
    public Fingerprint(byte[] source)
    {
        this(source, 160);
    }

    /**
     * Constructor with length - use SHAKE-256 (bitLength bits). This is the recommended one as it is also
     * produced by the FIPS API.
     *
     * @param source original data to calculate the fingerprint from.
     */
    public Fingerprint(byte[] source, int bitLength)
    {
        this.fingerprint = calculateFingerprint(source, bitLength);
    }

    public byte[] getFingerprint()
    {
        return Arrays.clone(fingerprint);
    }

    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i != fingerprint.length; i++)
        {
            if (i > 0)
            {
                sb.append(":");
            }
            sb.append(encodingTable[(fingerprint[i] >>> 4) & 0xf]);
            sb.append(encodingTable[fingerprint[i] & 0x0f]);
        }

        return sb.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof Fingerprint)
        {
            return Arrays.areEqual(((Fingerprint)o).fingerprint, fingerprint);
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(fingerprint);
    }

    /**
     * Return a byte array containing a calculated fingerprint for the passed in input data.
     * This calculation is compatible with the BC FIPS API.
     *
     * @param input data to base the fingerprint on.
     * @return a byte array containing a 160 bit fingerprint.
     */
    public static byte[] calculateFingerprint(byte[] input)
    {
        return calculateFingerprint(input, 160);
    }

    /**
     * Return a byte array containing a calculated fingerprint for the passed in input data.
     * This calculation is compatible with the BC FIPS API.
     *
     * @param input data to base the fingerprint on.
     * @param bitLength bit length of finger print to be produced.
     * @return a byte array containing a 20 byte fingerprint.
     */
    public static byte[] calculateFingerprint(byte[] input, int bitLength)
    {
        if (bitLength % 8 != 0)
        {
            throw new IllegalArgumentException("bitLength must be a multiple of 8");
        }

        SHAKEDigest digest = new SHAKEDigest(256);

        digest.update(input, 0, input.length);

        byte[] rv = new byte[bitLength / 8];

        digest.doFinal(rv, 0, bitLength / 8);

        return rv;
    }
}
