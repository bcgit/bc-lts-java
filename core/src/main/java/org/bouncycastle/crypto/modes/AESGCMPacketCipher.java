package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.*;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.dispose.Disposable;

import java.util.WeakHashMap;

public class AESGCMPacketCipher implements PacketCipher
{


    @Override
    public int getOutputSize(boolean direction, CipherParameters parameters, int len)
    {
        return 0;
    }


    @Override
    public void processPacket(boolean direction, CipherParameters parameters, byte[] input, int inOff, int len,
                              byte[] output, int outOff) throws PacketCipherException
    {

    }


}
