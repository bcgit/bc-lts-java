package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;

public interface SABERKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SABERParameterSpec
     */
    SABERParameterSpec getParameterSpec();
}
