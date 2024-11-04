package org.bouncycastle.pqc.jcajce.interfaces;



import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;

import java.security.Key;

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
