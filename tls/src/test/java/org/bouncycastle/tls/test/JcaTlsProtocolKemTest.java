package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JcaTlsProtocolKemTest
    extends TlsProtocolKemTest
{
    public JcaTlsProtocolKemTest()
    {
        super(new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom()));
    }
}
