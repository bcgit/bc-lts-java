package org.bouncycastle.crypto;

import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;

public interface NativeBlockCipherProvider
    extends NativeProvider
{
    GCMModeCipher createGCM();

    CBCModeCipher createCBC();

    CFBModeCipher createCFB(int bitSize);
}
