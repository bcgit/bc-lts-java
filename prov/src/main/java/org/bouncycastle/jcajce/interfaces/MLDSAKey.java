package org.bouncycastle.jcajce.interfaces;



import java.security.Key;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

public interface MLDSAKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MLDSAParameterSpec
     */
    MLDSAParameterSpec getParameterSpec();
}