package org.bouncycastle.crypto;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;

import org.bouncycastle.util.Properties;

/**
 * Native services maintains the relationship between implemented native features and
 * the feature definition strings.
 */
class DefaultNativeServices
        implements NativeServices
{
    private static final Logger LOG = Logger.getLogger(DefaultNativeServices.class.getName());

    /**
     * Default maximum number of retries for the hardware RNG instructions (RDSEED/RDRAND).
     */
    static final int DEFAULT_MAX_RNG_RETRIES = 1000;

    // Carries the default from the outset so that a re-entrant read during class initialisation
    // cannot see 0 - 0 is the "retry indefinitely" setting.
    private static volatile int maxRNGRetries = readMaxRNGRetries();

    // Carries its default from the outset so that a re-entrant read during class initialisation
    // cannot see null.
    private static final NativeServices.RandSource nativeRandSource = readNativeRandSource();

    private static Set<String> nativeFeatures = null;

    /**
     * Read the hardware entropy instruction from Properties.NATIVE_RAND_SOURCE. Where the
     * property is not set at all NativeServices.RandSource.AUTO is returned. Where it is set it
     * should hold one of RDRAND, RDSEED, AUTO or NONE. The match is exact, in the same way that
     * the retry property does not trim its value. Any other value is replaced with AUTO and a
     * warning naming the property is logged: this is read during class initialisation, and a
     * failure there would leave CryptoServicesRegistrar, and so the whole library, unusable for
     * the life of the JVM.
     */
    private static NativeServices.RandSource readNativeRandSource()
    {
        String value = Properties.getPropertyValue(Properties.NATIVE_RAND_SOURCE);

        if (value == null)
        {
            return NativeServices.RandSource.AUTO;
        }

        try
        {
            return NativeServices.RandSource.valueOf(value);
        }
        catch (IllegalArgumentException e)
        {
            LOG.warning(Properties.NATIVE_RAND_SOURCE + " must be one of RDRAND, RDSEED, AUTO or NONE, using AUTO: "
                + value);
            return NativeServices.RandSource.AUTO;
        }
    }

    /**
     * Return the hardware entropy instruction selected for the native entropy source.
     * <p>
     * The value comes from the system/security property org.bouncycastle.native.rand. Where that
     * property is not set at all the value is {@link NativeServices.RandSource#AUTO}, which uses
     * RDSEED where the CPU has it, otherwise RDRAND, otherwise the SecureRandom fallback. Where
     * it should hold one of RDRAND, RDSEED, AUTO or NONE; any other value is replaced with AUTO,
     * and a warning naming the property is logged.
     * </p>
     * <p>
     * RDRAND and RDSEED force the instruction: on a CPU that does not have the forced one, and
     * with the native layer otherwise on, the entropy source throws rather than quietly using the
     * other instruction. NONE turns the native entropy source off and selects the SecureRandom
     * fallback.
     * </p>
     *
     * @return the selected source.
     */
    static NativeServices.RandSource nativeRandSource()
    {
        return nativeRandSource;
    }

    /**
     * Read the RNG retry limit from Properties.NATIVE_RAND_MAX_RETRIES. Where the property is
     * not set at all DEFAULT_MAX_RNG_RETRIES is returned. Where it is set it should hold an
     * integer of 0 or greater. Any other value is replaced with DEFAULT_MAX_RNG_RETRIES and a
     * warning naming the property is logged, for the reason given for readNativeRandSource().
     */
    private static int readMaxRNGRetries()
    {
        int maxRetries;

        try
        {
            maxRetries = Properties.asInteger(Properties.NATIVE_RAND_MAX_RETRIES, DEFAULT_MAX_RNG_RETRIES);
        }
        catch (NumberFormatException e)
        {
            LOG.warning(Properties.NATIVE_RAND_MAX_RETRIES + " must be an integer of 0 or greater, using "
                + DEFAULT_MAX_RNG_RETRIES + ": " + e.getMessage());
            return DEFAULT_MAX_RNG_RETRIES;
        }

        if (maxRetries < 0)
        {
            LOG.warning(Properties.NATIVE_RAND_MAX_RETRIES + " must be an integer of 0 or greater, using "
                + DEFAULT_MAX_RNG_RETRIES + ": " + maxRetries);
            return DEFAULT_MAX_RNG_RETRIES;
        }

        return maxRetries;
    }

    /**
     * Return the maximum number of times a hardware RNG instruction (RDSEED/RDRAND) is retried
     * before a failure is declared. A return of 0 means the instruction is retried indefinitely.
     * <p>
     * The initial value comes from the system/security property
     * org.bouncycastle.native.rand.max_retries. Where that property is not set at all the value
     * is DEFAULT_MAX_RNG_RETRIES. Where it is set it must hold an integer of 0 or greater.
     * </p>
     * <p>
     * <b>Note</b>: the property is read in the static initialiser of this class. A value that is
     * not an integer of 0 or greater is replaced with DEFAULT_MAX_RNG_RETRIES, and a warning naming
     * the property is logged, rather than failing class initialisation, which would leave the
     * whole library unusable.
     * </p>
     *
     * @return the current RNG retry limit.
     */
    static int maxRNGRetries()
    {
        return maxRNGRetries;
    }

    /**
     * Set the retry limit for the current JVM. Internal, so that the bound can be driven from a
     * test without a fresh class loader; the shipped way to change it is the property.
     *
     * @param maxRetries the new limit, 0 or greater, where 0 selects retry without limit.
     */
    static void setMaxRNGRetries(int maxRetries)
    {
        if (maxRetries < 0)
        {
            throw new IllegalArgumentException("maxRetries cannot be negative: " + maxRetries);
        }

        maxRNGRetries = maxRetries;
    }

    @Override
    public String getStatusMessage()
    {
        if (NativeLoader.isNativeLibsAvailableForSystem() && NativeLoader.isNativeInstalled())
        {
            return "READY";
        }

        // The platform is supported but the load failed: say why.
        if (NativeLoader.isLoadFailure())
        {
            return NativeLoader.getNativeStatusMessage();
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

            if (NativeFeatures.hasGCMSIVHardwareSupport())
            {
                set.add(AES_GCMSIV);
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

            if (NativeFeatures.hasHardwareSHA256())
            {
                set.add(SHA2);
                set.add(SHA256);
            }

            if (NativeFeatures.hasHardwareSHA224())
            {
                set.add(SHA224);
            }

            if (NativeFeatures.hasHardwareSHA384())
            {
                set.add(SHA384);
            }

            if (NativeFeatures.hasHardwareSHA512())
            {
                set.add(SHA512);
            }

            if (NativeFeatures.hasHardwareSHA512())
            {
                set.add(SHA512);
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

            if (NativeFeatures.hasSHA3())
            {
                set.add(SHA3);
            }

            if (NativeFeatures.hasSHAKE())
            {
                set.add(SHAKE);
            }

            if (NativeFeatures.hasSlhDSASha256())
            {
                set.add(SLHDSA_SHA256);
            }
        }

        if (set.isEmpty())
        {
            set.add(NONE);
        }

        return Collections.unmodifiableSet(set);
    }
}