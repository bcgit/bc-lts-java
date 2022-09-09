package org.bouncycastle.crypto.engines;

public interface NativeEngine
{
    /**
     * Return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    String getAlgorithmName();
}
