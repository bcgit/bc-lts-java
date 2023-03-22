package org.bouncycastle.crypto;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * Native services maintains the relationship between implemented native features and
 * the feature definition strings.
 */
public class NativeServices
{
    public static final String RSA = "RSA";

    public static final String NRBG = "NRBG";
    public static final String DRBG = "DRBG";
    public static final String AES_ECB = "AES/ECB";
    public static final String AES_GCM = "AES/GCM";
    public static final String AES_CBC = "AES/CBC";
    public static final String AES_CFB = "AES/CFB";
    public static final String AES_CTR = "AES/CTR";

    public static final String SHA2 = "SHA2";

    public static final String NONE = "NONE";

    private static Set<String> nativeFeatures = null;

    public static String getStatusMessage()
    {
        if (NativeLoader.isNativeLibsAvailableForSystem())
        {
            if (NativeLoader.isNativeInstalled())
            {
                return "READY";
            }
            else
            {
                return NativeLoader.getNativeStatusMessage();
            }
        }

        // No support for platform / architecture
        return "UNSUPPORTED";
    }

    public static Set<String> getFeatureSet()
    {
        return getNativeFeatureSet();
    }

    public String getFeatureString()
    {
        return String.join(" ", getFeatureSet());
    }

    public static String getVariant()
    {
        return NativeLoader.getSelectedVariant();
    }

    public synchronized boolean hasService(String feature)
    {
        if (nativeFeatures == null)
        {
            nativeFeatures = getNativeFeatureSet();
        }

        return nativeFeatures.contains(feature);
    }

    public static String getBuildDate()
    {
        return NativeLibIdentity.getNativeBuiltTimeStamp();
    }

    static synchronized Set<String> getNativeFeatureSet()
    {
        TreeSet<String> set = new TreeSet<>();

        if (NativeFeatures.hasHardwareSeed())
        {
            set.add(NRBG);
        }
        if (NativeFeatures.hasHardwareRand())
        {
            set.add(DRBG);
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

        if (NativeFeatures.hasCTRHardwareSupport())
        {
            set.add(AES_CTR); // Only AES is needed for CTR mode.
        }

        if (NativeFeatures.hasHardwareSHA())
        {
            set.add(SHA2);
        }

        if (set.isEmpty())
        {
            set.add(NONE);
        }

        return Collections.unmodifiableSet(set);
    }
}