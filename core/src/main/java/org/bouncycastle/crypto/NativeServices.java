package org.bouncycastle.crypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class NativeServices
{
    public static final String SEED = "SEED";
    public static final String RAND = "RAND";
    public static final String AES_ECB = "AES/ECB";
    public static final String AES_GCM = "AES/GCM";
    public static final String AES_CBC = "AES/CBC";
    public static final String AES_CFB = "AES/CFB";

    public static final String ENTROPY = "ENTROPY";
    public static final String NONE = "NONE";

    private static Set<String> nativeFeatures = null;

    public static Set<String> getFeatureSet()
    {
        return getNativeFeatureSet();
    }

    public static String getStatusMessage()
    {
        return NativeLoader.getStatusMessage();
    }

    public static String getVariant()
    {
        return NativeLoader.getVariant();
    }

    public synchronized boolean hasFeature(String feature)
    {
        if (nativeFeatures == null)
        {
            nativeFeatures = getNativeFeatureSet();
        }

        return nativeFeatures.contains(feature);
    }

    static synchronized Set<String> getNativeFeatureSet()
    {
        HashSet<String> set = new HashSet<String>();

        if (NativeFeatures.hasHardwareSeed())
        {
            set.add(SEED);
        }
        if (NativeFeatures.hasHardwareRand())
        {
            set.add(RAND);
        }

        if (NativeFeatures.hasHardwareSeed() || NativeFeatures.hasHardwareRand())
        {
            set.add(ENTROPY);
        }

        if (NativeFeatures.hasAESHardwareSupport())
        {
            set.add(AES_ECB);
        }

        if (NativeFeatures.hasGCMHardwareSupport())
        {
            set.add(AES_GCM);
        }

        if (NativeFeatures.hasCBCHardwareSupport())
        {
            set.add(AES_CBC);
        }

        if (NativeFeatures.hasCFBHardwareSupport())
        {
            set.add(AES_CFB);
        }

        if (set.isEmpty())
        {
            set.add(NONE);
        }

        return Collections.unmodifiableSet(set);
    }
}
