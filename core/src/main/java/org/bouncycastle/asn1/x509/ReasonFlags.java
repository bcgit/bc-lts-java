package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.DERBitString;

/**
 * The ReasonFlags object.
 * <pre>
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 * </pre>
 */
public class ReasonFlags
    extends DERBitString
{
    public static final int unused                  = (1 << 7);
    public static final int keyCompromise           = (1 << 6);
    public static final int cACompromise            = (1 << 5);
    public static final int affiliationChanged      = (1 << 4);
    public static final int superseded              = (1 << 3);
    public static final int cessationOfOperation    = (1 << 2);
    public static final int certificateHold         = (1 << 1);
    public static final int privilegeWithdrawn      = (1 << 0);
    public static final int aACompromise            = (1 << 15);

    /**
     * @param reasons - the bitwise OR of the Key Reason flags giving the
     * allowed uses for the key.
     */
    public ReasonFlags(
        int reasons)
    {
        super(getBytes(reasons), getPadBits(reasons));
    }

    public ReasonFlags(
        ASN1BitString reasons)
    {
        super(reasons.getBytes(), reasons.getPadBits());
    }
}
