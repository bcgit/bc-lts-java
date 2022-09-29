package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

public interface FrodoKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FrodoParameterSpec
     */
    FrodoParameterSpec getParameterSpec();
}
