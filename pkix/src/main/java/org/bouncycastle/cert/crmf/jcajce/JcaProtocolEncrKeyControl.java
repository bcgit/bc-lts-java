package org.bouncycastle.cert.crmf.jcajce;

import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.ProtocolEncrKeyControl;

/**
 * JCA convenience for the protocol encryption key control - builds the control from a
 * {@link PublicKey} rather than from its SubjectPublicKeyInfo encoding.
 */
public class JcaProtocolEncrKeyControl
    extends ProtocolEncrKeyControl
{
    public JcaProtocolEncrKeyControl(PublicKey publicKey)
    {
        super(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }
}
