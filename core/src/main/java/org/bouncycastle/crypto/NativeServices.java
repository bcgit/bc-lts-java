package org.bouncycastle.crypto;

import java.util.Set;

public interface NativeServices
{
    String NRBG = "NRBG";
    String DRBG = "DRBG";

    String AES_ECB = "AES/ECB";
    String AES_GCM = "AES/GCM";
    String AES_GCMSIV = "AES/GCM-SIV";
    String AES_CBC = "AES/CBC";
    String AES_CFB = "AES/CFB";
    String AES_CTR = "AES/CTR";
    String AES_CCM = "AES/CCM";

    String AES_CBC_PC = "AES/CBC-PC";
    String AES_CCM_PC = "AES/CCM-PC";
    String AES_CFB_PC = "AES/CFB-PC";
    String AES_CTR_PC = "AES/CTR-PC";
    String AES_GCM_PC = "AES/GCM-PC";
    String AES_GCMSIV_PC = "AES/GCMSIV-PC";
    String SHA2 = "SHA2";

    String SHA256 = "SHA256";

    String SHA224 = "SHA224";

    String SHA512 = "SHA512";

    String SHA384 = "SHA384";

    String SHA3 = "SHA3";

    String SHAKE = "SHAKE";
    String MULACC = "MULACC";

    String SLHDSA_SHA256 = "SLHDSA_SHA256";

    String NONE = "NONE";

    /**
     * The hardware entropy instruction used by the native entropy source.
     */
    enum RandSource
    {
        /**
         * Use RDRAND, on a CPU with RDSEED as well.
         */
        RDRAND,
        /**
         * Use RDSEED.
         */
        RDSEED,
        /**
         * Use RDSEED where the CPU has it, otherwise RDRAND, otherwise the SecureRandom fallback.
         */
        AUTO,
        /**
         * Do not use the native entropy source, use the SecureRandom fallback.
         */
        NONE
    }

    /**
     * Return the hardware entropy instruction selected for the native entropy source.
     * <p>
     * The value comes from the system/security property org.bouncycastle.native.rand. Where that
     * property is not set at all the value is {@link RandSource#AUTO}, which uses RDSEED where the
     * CPU has it, otherwise RDRAND, otherwise the SecureRandom fallback. Where it is set it must
     * hold one of RDRAND, RDSEED, AUTO or NONE, any other value is rejected on first use.
     * </p>
     * <p>
     * RDRAND and RDSEED force the instruction: on a CPU that does not have the forced one, and
     * with the native layer otherwise on, the entropy source throws rather than quietly using the
     * other instruction. NONE turns the native entropy source off and selects the SecureRandom
     * fallback.
     * </p>
     * <p>
     * A default method, not an abstract one: the settings it reports are per-JVM rather than per
     * implementation, and an abstract addition would break anything downstream implementing this
     * interface.
     * </p>
     *
     * @return the selected source.
     */
    default RandSource getNativeRandSource()
    {
        return DefaultNativeServices.nativeRandSource();
    }

    /**
     * Return the maximum number of times a hardware RNG instruction (RDSEED/RDRAND) is retried
     * before a failure is declared. A return of 0 means the instruction is retried indefinitely.
     * <p>
     * The value comes from the system/security property org.bouncycastle.native.rand.max_retries.
     * Where that property is not set at all the value is the shipped default. Where it is set it
     * must hold an integer of 0 or greater, any other value is rejected on first use.
     * </p>
     * <p>
     * A default method, for the same reason as {@link #getNativeRandSource()}.
     * </p>
     *
     * @return the current RNG retry limit.
     */
    default int getMaxRNGRetries()
    {
        return DefaultNativeServices.maxRNGRetries();
    }

    String getStatusMessage();

    Set<String> getFeatureSet();

    String getVariant();

    String[][] getVariantSelectionMatrix();

    boolean hasService(String feature);

    String getBuildDate();

    String getLibraryIdent();

    /**
     * Returns true if some native support is ready and enabled.
     * Consult feature set for details.
     *
     * @return true if some hardware support is enabled.
     */
    boolean isEnabled();

    /**
     * Returns true if some native support has been installed.
     *
     * @return true if some hardware support is installed.
     */
    boolean isInstalled();

    /**
     * Returns true if there are native libraries available for this
     * platform and architecture.
     *
     * @return true if available, false if not.
     */
    boolean isSupported();
}
