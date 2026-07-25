package org.bouncycastle.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.AsymmetricKeyWrapper;

public abstract class KEMKeyWrapper
    extends AsymmetricKeyWrapper
{
    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        super(algorithmId);
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();

    /**
     * Return the optional user keying material to carry in the KEMRecipientInfo, or null if none is
     * set (RFC 9629 sec. 3: ukm is OPTIONAL).
     * <p>
     * Concrete rather than abstract, deliberately: this class is public and adding an abstract
     * method to it would break any existing subclass outside the library. Wrappers that support
     * user keying material override this.
     */
    public byte[] getUkm()
    {
        return null;
    }
}
