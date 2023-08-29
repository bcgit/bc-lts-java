package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESCFBModePacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

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
        return getOutputSize(encryption, len);
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        byte[] iv, key;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                key = ((KeyParameter)ivParam.getParameters()).getKey();
            }
            else
            {
                throw PacketCipherException.from(new IllegalArgumentException("CFB cipher unitialized"));
            }
            iv = ivParam.getIV().clone();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CFB"));
        }
        int result;
        try
        {
            result = processPacket(encryption, key, key.length, iv, input, inOff, len, output, outOff);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        return result;
    }

    static native int getOutputSize(boolean encryption, int len);

    static native int processPacket(boolean encryption, byte[] key, int keyLen, byte[] nonce, byte[] in, int inOff, int inLen, byte[] out, int outOff);

    @Override
    public String toString()
    {
        return "CFB Packet Cipher (Native)";
    }
}
