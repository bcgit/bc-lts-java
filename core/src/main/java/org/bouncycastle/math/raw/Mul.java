package org.bouncycastle.math.raw;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

public class Mul
{
    public static void multiplyAcc(long[] x, int xOff, long[] y, int yOff, long[] z)
    {
        cmulAcc(x, xOff, y, yOff, z);
    }

    private static native void cmulAcc(long[] x, int xOff, long[] y, int yOff, long[] z);

}
