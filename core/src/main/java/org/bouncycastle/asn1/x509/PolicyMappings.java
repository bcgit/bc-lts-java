package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * PolicyMappings V3 extension, described in RFC3280.
 * <pre>
 *    PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 * </pre>
 *
 * @see <a href="https://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a>
 */
public class PolicyMappings
    extends ASN1Object
{
    ASN1Sequence seq = null;

    public static PolicyMappings getInstance(Object obj)
    {
        if (obj instanceof PolicyMappings)
        {
            return (PolicyMappings)obj;
        }
        if (obj != null)
        {
            return new PolicyMappings(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Creates a new <code>PolicyMappings</code> instance.
     *
     * @param seq an <code>ASN1Sequence</code> constructed as specified
     *            in RFC 3280
     */
    private PolicyMappings(ASN1Sequence seq)
    {
        this.seq = seq;
    }

    public PolicyMappings(CertPolicyId issuerDomainPolicy, CertPolicyId subjectDomainPolicy)
    {
        ASN1EncodableVector dv = new ASN1EncodableVector(2);
        dv.add(issuerDomainPolicy);
        dv.add(subjectDomainPolicy);

        seq = new DERSequence(new DERSequence(dv));
    }

    public PolicyMappings(CertPolicyId[] issuerDomainPolicy, CertPolicyId[] subjectDomainPolicy)
    {
        ASN1EncodableVector dev = new ASN1EncodableVector(issuerDomainPolicy.length);

        for (int i = 0; i != issuerDomainPolicy.length; i++)
        {
            ASN1EncodableVector dv = new ASN1EncodableVector(2);
            dv.add(issuerDomainPolicy[i]);
            dv.add(subjectDomainPolicy[i]);
            dev.add(new DERSequence(dv));
        }

        seq = new DERSequence(dev);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
