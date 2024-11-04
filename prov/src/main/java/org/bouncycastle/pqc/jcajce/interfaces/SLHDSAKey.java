package org.bouncycastle.pqc.jcajce.interfaces;



import org.bouncycastle.pqc.jcajce.spec.SLHDSAParameterSpec;

import java.security.Key;

public interface SLHDSAKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SLHDSAParameterSpec
     */
    SLHDSAParameterSpec getParameterSpec();
}
