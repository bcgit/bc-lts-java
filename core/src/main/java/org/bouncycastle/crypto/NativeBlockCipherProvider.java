package org.bouncycastle.crypto;

import org.bouncycastle.crypto.modes.*;

public interface NativeBlockCipherProvider
    extends NativeServiceProvider
{
    GCMModeCipher createGCM();

    CBCModeCipher createCBC();

    CFBModeCipher createCFB(int bitSize);

    CTRModeCipher createCTR();
}
