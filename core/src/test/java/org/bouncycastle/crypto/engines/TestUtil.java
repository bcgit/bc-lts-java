package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

public class TestUtil
{
    public static boolean hasNativeService(String service)
    {
        return CryptoServicesRegistrar.hasEnabledService(service);
    }

    public static String errorMsg()
    {
        return getNativeFeatureString();
    }

    public static String getNativeFeatureString()
    {
        return String.join(" ", CryptoServicesRegistrar.getNativeServices().getFeatureSet());
    }
}
