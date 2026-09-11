package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

public class ElGamalPrivateKeyParameters
    extends ElGamalKeyParameters
    implements Destroyable
{
    private BigInteger      x;

    private volatile boolean destroyed;
    private int destroyedHashCode;

    public ElGamalPrivateKeyParameters(
        BigInteger      x,
        ElGamalParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        BigInteger value = x;

        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    public boolean equals(
        Object  obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof ElGamalPrivateKeyParameters))
        {
            return false;
        }

        ElGamalPrivateKeyParameters  pKey = (ElGamalPrivateKeyParameters)obj;

        BigInteger thisX = this.x;
        BigInteger otherX = pKey.x;

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (destroyed || pKey.destroyed || thisX == null || otherX == null)
        {
            return false;
        }

        if (!otherX.equals(thisX))
        {
            return false;
        }

        return super.equals(obj);
    }
    
    public synchronized int hashCode()
    {
        BigInteger value = x;

        if (value == null)
        {
            return destroyedHashCode;
        }

        ElGamalParameters params = getParameters();
        BigInteger y = params.getG().modPow(value, params.getP());

        return y.hashCode() ^ super.hashCode();
    }

    /**
     * Destroy this object, dropping its reference to the private value.
     * <p>
     * As {@link BigInteger} is immutable the private value cannot be zeroized in place;
     * destruction drops the internal reference so the value becomes unreachable (cleared on
     * garbage collection). The (public) domain parameters are retained. After destruction
     * {@link #getX()} throws {@link IllegalStateException}, {@link #hashCode()} retains its
     * pre-destruction value and the object is equal only to itself.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            // freeze the hash before the private value is dropped, so hash containers holding
            // this key keep working.
            try
            {
                this.destroyedHashCode = hashCode();
            }
            catch (RuntimeException e)
            {
                this.destroyedHashCode = -1;
            }

            destroyed = true;
            this.x = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }
}
