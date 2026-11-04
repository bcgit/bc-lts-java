package org.bouncycastle.cert.crmf.jcajce;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.OldCertIDControl;

/**
 * JCA convenience for the old certificate ID control - builds the control from the certificate
 * being replaced, or from its issuer and serial number, rather than from a CertId.
 */
public class JcaOldCertIDControl
    extends OldCertIDControl
{
    public JcaOldCertIDControl(X509Certificate certificate)
    {
        this(certificate.getIssuerX500Principal(), certificate.getSerialNumber());
    }

    public JcaOldCertIDControl(X500Principal issuer, BigInteger serialNumber)
    {
        super(X500Name.getInstance(issuer.getEncoded()), serialNumber);
    }
}
