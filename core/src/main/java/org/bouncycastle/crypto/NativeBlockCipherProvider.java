package org.bouncycastle.crypto;

import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;

public interface NativeBlockCipherProvider
    extends NativeServiceProvider
{
    GCMModeCipher createGCM();

    CBCModeCipher createCBC();

    CFBModeCipher createCFB(int bitSize);

    SkippingStreamCipher createCTR();
}
