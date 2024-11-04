package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class MLKEMKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MLKEMParameters params;

    public MLKEMKeyGenerationParameters(
        SecureRandom random,
        MLKEMParameters mlkemParameters)
    {
        super(random, 256);
        this.params = mlkemParameters;
    }

    public MLKEMParameters getParameters()
    {
        return params;
    }
}
