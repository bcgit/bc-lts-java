package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

public class GOST3410PrivateKeyParameters
        extends GOST3410KeyParameters
        implements Destroyable
{
    private BigInteger      x;

    private volatile boolean destroyed;

    public GOST3410PrivateKeyParameters(
        BigInteger      x,
        GOST3410Parameters   params)
    {
        super(true, params);

        this.x = validate(x, params);
    }

    // as with DSA, x is multiplied and reduced modulo q when a signature is formed, in a
    // constant-time form that requires it already reduced; the key carries the parameters that
    // bound it, so the check belongs here
    private static BigInteger validate(BigInteger x, GOST3410Parameters params)
    {
        if (x != null && params != null
            && (x.signum() <= 0 || x.compareTo(params.getQ()) >= 0))
        {
            throw new IllegalArgumentException("x must be in [1, q-1]");
        }

        return x;
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

    /**
     * Destroy this object, dropping its reference to the private value.
     * <p>
     * As {@link BigInteger} is immutable the private value cannot be zeroized in place;
     * destruction drops the internal reference so the value becomes unreachable (cleared on
     * garbage collection). The (public) domain parameters are retained. After destruction
     * {@link #getX()} throws {@link IllegalStateException}.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            this.x = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }
}
