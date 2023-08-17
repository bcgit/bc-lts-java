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

    String AES_CBC_PC = "AES/CBC PC";
    String AES_CCM_PC = "AES/CCM PC";
    String AES_CFB_PC = "AES/CFB PC";
    String AES_CTR_PC = "AES/CTR PC";
    String AES_GCM_PC = "AES/GCM PC";
    String AES_GCMSIV_PC = "AES/GCMSIV PC";
    String SHA2 = "SHA2";
    String MULACC = "MULACC";

    String NONE = "NONE";

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
