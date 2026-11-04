package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Carrier for a protocol encryption key control.
 */
public class ProtocolEncrKeyControl
    implements Control
{
    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_protocolEncrKey;

    private final SubjectPublicKeyInfo publicKeyInfo;

    /**
     * Basic constructor - build from the public key to use for protocol encryption.
     *
     * @param publicKeyInfo the public key to use for protocol encryption.
     */
    public ProtocolEncrKeyControl(SubjectPublicKeyInfo publicKeyInfo)
    {
        this.publicKeyInfo = publicKeyInfo;
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_protocolEncrKey
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the public key associated with this control.
     *
     * @return a SubjectPublicKeyInfo structure.
     */
    public ASN1Encodable getValue()
    {
        return publicKeyInfo;
    }
}
