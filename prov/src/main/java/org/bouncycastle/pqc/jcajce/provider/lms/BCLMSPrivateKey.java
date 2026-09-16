package org.bouncycastle.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class BCLMSPrivateKey
    implements PrivateKey, LMSPrivateKey, Destroyable
{
    private static final long serialVersionUID = 8568701712864512338L;

    private transient LMSKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCLMSPrivateKey(
        LMSKeyParameters keyParams)
    {
        this.keyParams = (keyParams instanceof HSSPrivateKeyParameters) ? (HSSPrivateKeyParameters)keyParams : new HSSPrivateKeyParameters((LMSPrivateKeyParameters)keyParams, ((LMSPrivateKeyParameters)keyParams).getIndex(), ((LMSPrivateKeyParameters)keyParams).getIndex() + ((LMSPrivateKeyParameters)keyParams).getUsagesRemaining());
    }

    public BCLMSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (LMSKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public long getIndex()
    {
        if (getUsagesRemaining() == 0)
        {
            throw new IllegalStateException("key exhausted");
        }

        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)keyParams).getIndex();
        }
        return ((HSSPrivateKeyParameters)keyParams).getIndex();
    }

    public long getUsagesRemaining()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)keyParams).getUsagesRemaining();
        }
        return ((HSSPrivateKeyParameters)keyParams).getUsagesRemaining();
    }

    public LMSPrivateKey extractKeyShard(int usageCount)
    {
        // an HSS key refuses this itself once destroyed; an LMS one would hand back a shard
        // sharing the master secret array that destroy() has just cleared, so check here and the
        // JCA level behaves the same either way.
        checkDestroyed();

        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return new BCLMSPrivateKey(((LMSPrivateKeyParameters)keyParams).extractKeyShard(usageCount));
        }
        return new BCLMSPrivateKey(((HSSPrivateKeyParameters)keyParams).extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "LMS";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        checkDestroyed();

        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCLMSPrivateKey)
        {
            BCLMSPrivateKey otherKey = (BCLMSPrivateKey)o;

            // a destroyed key no longer exposes its value, so it is only equal to itself.
            if (isDestroyed() || otherKey.isDestroyed())
            {
                return false;
            }

            try
            {
                return Arrays.constantTimeAreEqual(keyParams.getEncoded(), otherKey.keyParams.getEncoded());
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("unable to perform equals", e);     // should never happen.
            }
        }

        return false;
    }

    public int hashCode()
    {
        return new BCLMSPublicKey(((HSSPrivateKeyParameters)keyParams).getPublicKey()).hashCode();
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public int getLevels()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return 1;
        }
        else
        {
            return ((HSSPrivateKeyParameters)keyParams).getL();
        }
    }

    /**
     * Destroy this key, zeroizing the secret key material it holds.
     * <p>
     * The master secret of every tree in the hierarchy is zeroized; the key identifiers, indexes,
     * chaining signatures and cached tree nodes are retained, so {@link #getIndex()},
     * {@link #getUsagesRemaining()} and {@link #getLevels()} keep working. After destruction
     * {@link #isDestroyed()} returns true, and {@link #getEncoded()} and
     * {@link #extractKeyShard(int)} throw {@link IllegalStateException}, so the key can no longer
     * be serialized. Shards extracted before destruction are independent copies where the
     * underlying key is an HSS one; an LMS shard shares its parent's master secret array and is
     * invalidated with it.
     */
    public synchronized void destroy()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            ((LMSPrivateKeyParameters)keyParams).destroy();
        }
        else
        {
            ((HSSPrivateKeyParameters)keyParams).destroy();
        }
    }

    public boolean isDestroyed()
    {
        if (keyParams instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)keyParams).isDestroyed();
        }
        return ((HSSPrivateKeyParameters)keyParams).isDestroyed();
    }

    private void checkDestroyed()
    {
        if (isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        try
        {
            out.writeObject(this.getEncoded());
        }
        catch (IllegalStateException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }
}
