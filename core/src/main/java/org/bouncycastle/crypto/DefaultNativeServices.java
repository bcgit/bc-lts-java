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
            if (NativeLoader.isJavaSupportOnly())
            {
                nativeFeatures = Collections.singleton(NONE);
            }
            else
            {
                nativeFeatures = getNativeFeatureSet();
            }
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

        if (!NativeLoader.isJavaSupportOnly())
        {
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

            if (NativeFeatures.hasCCMHardwareSupport())
            {
                set.add(AES_CCM);
            }

            if (NativeFeatures.hasCBCPCHardwareSupport())
            {
                set.add(AES_CBC_PC);
            }

            if (NativeFeatures.hasCCMPCHardwareSupport())
            {
                set.add(AES_CCM_PC);
            }

            if (NativeFeatures.hasCFBPCHardwareSupport())
            {
                set.add(AES_CFB_PC);
            }

            if (NativeFeatures.hasCTRPCHardwareSupport())
            {
                set.add(AES_CTR_PC);
            }

            if (NativeFeatures.hasGCMPCHardwareSupport())
            {
                set.add(AES_GCM_PC);
            }

            if (NativeFeatures.hasGCMSIVPCHardwareSupport())
            {
                set.add(AES_GCMSIV_PC);
            }

            if (NativeFeatures.hasMultiplyAcc())
            {
                set.add(MULACC);
            }

        }

        if (set.isEmpty())
        {
            set.add(NONE);
        }

        return Collections.unmodifiableSet(set);
    }
}