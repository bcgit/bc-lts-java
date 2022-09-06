package org.bouncycastle.crypto;

public enum CryptoServicePurpose
{
    AGREEMENT,
    ENCRYPTION,
    DECRYPTION,
    KEYGEN,
    SIGNING,
    VERIFYING,
    PRF,
    ANY,
    NATIVE_LOADING
}
