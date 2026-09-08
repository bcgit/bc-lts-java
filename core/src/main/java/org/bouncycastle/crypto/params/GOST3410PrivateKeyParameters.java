package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class GOST3410PrivateKeyParameters
        extends GOST3410KeyParameters
{
    private BigInteger      x;

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
        return x;
    }
}
