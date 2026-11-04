package org.bouncycastle.cert.crmf;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Carrier for an old certificate ID control, naming the certificate a request is asking to have
 * replaced - RFC 4211 sec. 6.5.
 */
public class OldCertIDControl
    implements Control
{
    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_oldCertID;

    private final CertId certId;

    /**
     * Basic constructor - build from the ID of the certificate to be replaced.
     *
     * @param certId the issuer and serial number of the certificate to be replaced.
     */
    public OldCertIDControl(CertId certId)
    {
        this.certId = certId;
    }

    /**
     * Basic constructor - build from the issuer and serial number of the certificate to be
     * replaced.
     *
     * @param issuer the issuer of the certificate to be replaced.
     * @param serialNumber the serial number of the certificate to be replaced.
     */
    public OldCertIDControl(X500Name issuer, BigInteger serialNumber)
    {
        this(new CertId(new GeneralName(issuer), serialNumber));
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_oldCertID
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the certificate ID associated with this control.
     *
     * @return a CertId structure.
     */
    public ASN1Encodable getValue()
    {
        return certId;
    }

    /**
     * Return the certificate ID associated with this control.
     *
     * @return a CertId structure.
     */
    public CertId getCertId()
    {
        return certId;
    }
}
