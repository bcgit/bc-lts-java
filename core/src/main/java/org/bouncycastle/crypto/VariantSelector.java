package org.bouncycastle.crypto;

/**
 * A class with native backing that examines the machine
 * and returns the best variant to deploy if none is forced.
 */
public class VariantSelector
{
    static native String getBestVariantName();
}
