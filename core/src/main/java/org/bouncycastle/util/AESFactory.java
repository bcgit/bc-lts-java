package org.bouncycastle.util;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

public class AESFactory
{
    public static BlockCipher createECB()
    {
        return new AESEngine();
    }

    public static CBCBlockCipher createCBC()
    {
        return new CBCBlockCipher(new AESEngine());
    }

    public static GCMBlockCipher createGCM()
    {
        return new GCMBlockCipher(new AESEngine());
    }
}
