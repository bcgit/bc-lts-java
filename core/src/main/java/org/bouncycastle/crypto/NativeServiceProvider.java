package org.bouncycastle.crypto;

public interface NativeServiceProvider
{
    /**
     * Return the name of the algorithm the provider supports.
     *
     * @return the name of the algorithm for the provider.
     */
    String getAlgorithmName();
}
