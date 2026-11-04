package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * The AlgorithmIdentifier parameters for GOST R 34.10-2001 and GOST R 34.10-2012 keys.
 * <p>
 * This type covers two structures:
 * <pre>
 * GostR3410-2001-PublicKeyParameters ::= SEQUENCE {      -- RFC 4491, Section 2.3.2
 *     publicKeyParamSet   OBJECT IDENTIFIER,
 *     digestParamSet      OBJECT IDENTIFIER,
 *     encryptionParamSet  OBJECT IDENTIFIER DEFAULT id-Gost28147-89-CryptoPro-A-ParamSet
 * }
 *
 * GostR3410-2012-PublicKeyParameters ::= SEQUENCE {      -- RFC 9215, Section 4.2
 *     publicKeyParamSet   OBJECT IDENTIFIER,
 *     digestParamSet      OBJECT IDENTIFIER OPTIONAL
 * }
 * </pre>
 * digestParamSet and encryptionParamSet are consecutive, untagged, and of the same type, so a second
 * element cannot be distinguished by type alone. It is always digestParamSet: the 2001 structure requires
 * digestParamSet ahead of the DEFAULT encryptionParamSet, and the 2012 structure has no encryptionParamSet.
 * <p>
 * RFC 9215 requires digestParamSet to be omitted for id-tc26-gost-3410-12-256-paramSetB/C/D and says it
 * should be omitted for paramSetA and the 512-bit parameter sets. A digestParamSet present alongside any of
 * those is nevertheless accepted on decode, since older implementations emitted one.
 */
public class GOST3410PublicKeyAlgParameters
    extends ASN1Object
{
    private ASN1ObjectIdentifier  publicKeyParamSet;
    private ASN1ObjectIdentifier  digestParamSet;
    private ASN1ObjectIdentifier  encryptionParamSet;

    public static GOST3410PublicKeyAlgParameters getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST3410PublicKeyAlgParameters getInstance(
        Object obj)
    {
        if (obj instanceof GOST3410PublicKeyAlgParameters)
        {
            return (GOST3410PublicKeyAlgParameters)obj;
        }

        if(obj != null)
        {
            return new GOST3410PublicKeyAlgParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public GOST3410PublicKeyAlgParameters(
        ASN1ObjectIdentifier  publicKeyParamSet,
        ASN1ObjectIdentifier  digestParamSet)
    {
        this(publicKeyParamSet, digestParamSet, null);
    }

    /**
     * @param publicKeyParamSet the public key parameter set; required.
     * @param digestParamSet the digest parameter set; may be null for GOST R 34.10-2012 keys (RFC 9215,
     *                       Section 4.2), but is required for GOST R 34.10-2001 keys (RFC 4491,
     *                       Section 2.3.2).
     * @param encryptionParamSet the encryption parameter set; may be null. Only meaningful with a non-null
     *                           digestParamSet, since it can only be encoded as the third element.
     */
    public GOST3410PublicKeyAlgParameters(
        ASN1ObjectIdentifier  publicKeyParamSet,
        ASN1ObjectIdentifier  digestParamSet,
        ASN1ObjectIdentifier  encryptionParamSet)
    {
        if (publicKeyParamSet == null)
        {
            throw new NullPointerException("'publicKeyParamSet' cannot be null");
        }
        if (digestParamSet == null && encryptionParamSet != null)
        {
            throw new IllegalArgumentException("encryptionParamSet requires digestParamSet");
        }

        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = encryptionParamSet;
    }

    private GOST3410PublicKeyAlgParameters(
        ASN1Sequence  seq)
    {
        int count = seq.size();
        if (count < 1 || count > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        this.publicKeyParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        // NOTE: Two consecutive untagged OPTIONALs of the same type cannot be told apart by the reads below;
        // the greedy assignment (a second element is always digestParamSet) is correct here only because of
        // the structure rules recorded in the class documentation.
        if (count > 1)
        {
            this.digestParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        }
        if (count > 2)
        {
            this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(2));
        }
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return publicKeyParamSet;
    }

    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(publicKeyParamSet);

        if (digestParamSet != null)
        {
            v.add(digestParamSet);
        }

        if (encryptionParamSet != null)
        {
            v.add(encryptionParamSet);
        }

        return new DERSequence(v);
    }
}
