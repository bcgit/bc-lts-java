package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

public class DigTest
{
    public static void main(String[] args)
    {
        Xof xof = new SHAKEDigest(128);

        System.err.println(xof.getAlgorithmName());
    }
}
