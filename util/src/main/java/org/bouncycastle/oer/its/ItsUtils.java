package org.bouncycastle.oer.its;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class ItsUtils
{

    /**
     * <pre>
     *     OCTET STRING (SIZE(n))
     * </pre>
     */
    public static byte[] octetStringFixed(byte[] octets, int n)
    {
        if (octets.length != n)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return octets;
    }

    /**
     * <pre>
     *     OCTET STRING (SIZE(1..32))
     * </pre>
     */
    public static byte[] octetStringFixed(byte[] octets)
    {
        if (octets.length < 1 || octets.length > 32)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return Arrays.clone(octets);
    }

    public static ASN1Sequence toSequence(List objs)
    {
        return new DERSequence((ASN1Encodable[])objs.toArray(new ASN1Encodable[0]));
    }

    public static ASN1Sequence toSequence(ASN1Encodable... objs)
    {
        return new DERSequence(objs);
    }
}
