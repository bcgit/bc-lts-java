package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;

/**
 * Base native digest provides constraint verification for native digests.
 */
public abstract class BaseNativeDigest implements Digest
{
    private final CryptoServicePurpose purpose;
    private final int bitLen;

    public BaseNativeDigest(int bitLen, CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        this.bitLen = bitLen;
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    protected final CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, bitLen, purpose);
    }
}
