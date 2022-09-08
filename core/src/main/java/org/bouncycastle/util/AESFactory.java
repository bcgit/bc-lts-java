package org.bouncycastle.util;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCBC;
import org.bouncycastle.crypto.engines.AESNativeEngine;
import org.bouncycastle.crypto.engines.AESNativeGCM;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMCipher;

public class AESFactory
{
    public static BlockCipher createECB()
    {
        if (CryptoServicesRegistrar.getNativeServices().hasFeature("AES/ECB"))
        {
            return new AESNativeEngine();
        }

        return new AESEngine();
    }

    public static BlockCipher createCBC()
    {
        if (CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CBC"))
        {
            return new AESNativeCBC();
        }

        return new CBCBlockCipher(new AESEngine());
    }

    public static GCMCipher createGCM()
    {
        if (CryptoServicesRegistrar.getNativeServices().hasFeature("AES/GCM"))
        {
            return new AESNativeGCM();
        }
        return new GCMBlockCipher(new AESEngine());
    }
}
