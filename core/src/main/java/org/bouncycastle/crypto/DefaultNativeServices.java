package org.bouncycastle.crypto;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * Native services maintains the relationship between implemented native features and
 * the feature definition strings.
 */
class DefaultNativeServices
    implements NativeServices
{

    private static Set<String> nativeFeatures = null;

    @Override
    public String getStatusMessage()
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

    @Override
    public Set<String> getFeatureSet()
    {
        return getNativeFeatureSet();
    }

    @Override
    public String getVariant()
    {
        return NativeLoader.getSelectedVariant();
    }

    @Override
    public String[][] getVariantSelectionMatrix()
    {
        return VariantSelector.getFeatureMatrix();
    }

    @Override
    public boolean hasService(String feature)
    {
        if (nativeFeatures == null)
        {
            nativeFeatures = getNativeFeatureSet();
        }

        return nativeFeatures.contains(feature);
    }

    @Override
    public String getBuildDate()
    {
        return NativeLibIdentity.getNativeBuiltTimeStamp();
    }

    public String getLibraryIdent()
    {
        return NativeLibIdentity.getLibraryIdent();
    }

    public boolean isEnabled()
    {
        return NativeLoader.isNativeAvailable();
    }

    public boolean isInstalled()
    {
        return NativeLoader.isNativeInstalled();
    }

    public boolean isSupported()
    {
        return NativeLoader.isNativeLibsAvailableForSystem();
    }

    static Set<String> getNativeFeatureSet()
    {
        TreeSet<String> set = new TreeSet<String>();

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