package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DSAPrivateKeyParameters
    extends DSAKeyParameters
{
    private BigInteger      x;

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
        return x;
    }
}
