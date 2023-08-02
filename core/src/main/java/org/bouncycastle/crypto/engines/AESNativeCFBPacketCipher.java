package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESCFBModePacketCipher;

public class AESNativeCFBPacketCipher
    extends PacketCipherEngine
    implements AESCFBModePacketCipher
{
    public static AESCFBModePacketCipher newInstance()
    {
        return new AESNativeCFBPacketCipher();
    }

    private AESNativeCFBPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        return 0;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        return 0;
    }
}
