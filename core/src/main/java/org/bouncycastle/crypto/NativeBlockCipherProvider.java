package org.bouncycastle.crypto;

import org.bouncycastle.crypto.modes.*;

public interface NativeBlockCipherProvider
    extends NativeServiceProvider
{
    GCMModeCipher createGCM();

    GCMSIVModeCipher createGCMSIV();

    CBCModeCipher createCBC();

    CFBModeCipher createCFB(int bitSize);

    CTRModeCipher createCTR();

    CCMModeCipher createCCM();

    EAXModeCipher createEAX();

    OCBModeCipher createOCB();
}
