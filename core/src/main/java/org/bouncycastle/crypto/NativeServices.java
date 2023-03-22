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

    String SHA2 = "SHA2";

    String NONE = "NONE";

    String getStatusMessage();

    Set<String> getFeatureSet();

    String getVariant();

    String[][] getVariantSelectionMatrix();

    boolean hasService(String feature);

    String getBuildDate();
}
