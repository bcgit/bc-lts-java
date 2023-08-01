package org.bouncycastle.crypto;


import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.modes.CTRModeCipher;

public interface NativeBlockCipherProvider
    extends NativeServiceProvider
{
    GCMModeCipher createGCM();

    CBCModeCipher createCBC();

    CFBModeCipher createCFB(int bitSize);

    CCMModeCipher createCCM();
    CTRModeCipher createCTR();
}
