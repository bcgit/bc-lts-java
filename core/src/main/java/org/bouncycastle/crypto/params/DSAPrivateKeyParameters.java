package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

public class DSAPrivateKeyParameters
    extends DSAKeyParameters
    implements Destroyable
{
    private BigInteger      x;

    private volatile boolean destroyed;

    public DSAPrivateKeyParameters(
        BigInteger      x,
        DSAParameters   params)
    {
        super(true, params);

        this.x = validate(x, params);
    }   

    // x is multiplied and reduced modulo q when a signature is formed, in a constant-time form
    // that requires it already reduced, and FIPS 186-4 sec. 4.1 puts it in [1, q-1] in any case.
    // Unlike the ECCSI signing key, a DSA key carries the parameters that bound it, so the check
    // belongs here rather than at the point of use.
    private static BigInteger validate(BigInteger x, DSAParameters params)
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
