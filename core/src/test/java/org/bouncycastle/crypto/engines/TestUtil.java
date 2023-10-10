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

    public static boolean skipPS() {
         return "true".equals(System.getProperty("org.bouncycastle.test.skip_ps"));
    }


    public static boolean isSkipSet(String label)
    {
        for (String item : System.getProperty("test.bclts.ignore.native", "").split(","))
        {
            item = item.trim();
            if (item.equalsIgnoreCase(label))
            {
                return true;
            }
        }
        return false;
    }

}
