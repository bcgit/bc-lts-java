package org.bouncycastle.crypto;

import java.util.Set;

public interface NativeServices
{
    String NRBG = "NRBG";
    String DRBG = "DRBG";

    String AES_ECB = "AES/ECB";
    String AES_GCM = "AES/GCM";
    String AES_CBC = "AES/CBC";
    String AES_CFB = "AES/CFB";
    String AES_CTR = "AES/CTR";
    String AES_CCM = "AES/CCM";

    String SHA2 = "SHA2";

    String SHA256 = "SHA256";

    String SHA224 = "SHA224";

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
