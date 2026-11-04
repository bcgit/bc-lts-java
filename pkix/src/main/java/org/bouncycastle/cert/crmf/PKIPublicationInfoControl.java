package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;
import org.bouncycastle.asn1.crmf.SinglePubInfo;

/**
 * Carrier for a publication information control, saying whether and where the CA should publish
 * the certificate it issues - RFC 4211 sec. 6.3.
 */
public class PKIPublicationInfoControl
    implements Control
{
    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_pkiPublicationInfo;

    private final PKIPublicationInfo publicationInfo;

    /**
     * Basic constructor - build from the publication information to use.
     *
     * @param publicationInfo the publication information for the certificate.
     */
    public PKIPublicationInfoControl(PKIPublicationInfo publicationInfo)
    {
        this.publicationInfo = publicationInfo;
    }

    /**
     * Basic constructor - build from the locations the certificate is to be published at,
     * which asks for publication (pleasePublish). A null or empty array asks for publication
     * without saying where ("dontCare"); use {@link #dontPublish()} to ask for none.
     *
     * @param pubInfos the locations to publish the certificate at.
     */
    public PKIPublicationInfoControl(SinglePubInfo[] pubInfos)
    {
        this(new PKIPublicationInfo(pubInfos == null || pubInfos.length == 0 ? null : pubInfos));
    }

    /**
     * Return a control asking the CA not to publish the certificate.
     *
     * @return a control carrying the dontPublish action.
     */
    public static PKIPublicationInfoControl dontPublish()
    {
        return new PKIPublicationInfoControl(new PKIPublicationInfo(PKIPublicationInfo.dontPublish));
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_pkiPublicationInfo
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the publication information associated with this control.
     *
     * @return a PKIPublicationInfo structure.
     */
    public ASN1Encodable getValue()
    {
        return publicationInfo;
    }

    /**
     * Return the publication information associated with this control.
     *
     * @return a PKIPublicationInfo structure.
     */
    public PKIPublicationInfo getPublicationInfo()
    {
        return publicationInfo;
    }
}
