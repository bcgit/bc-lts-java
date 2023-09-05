package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESCBCModePacketCipher;
import org.bouncycastle.crypto.modes.AESCCMModePacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESNativeCBCPacketCipher
        implements PacketCipher, AESCBCModePacketCipher
{


    public AESNativeCBCPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (!(parameters instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException("invalid parameters passed to CBC");
        }

        return getOutputSize(encryption, len);
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
            throws PacketCipherException
    {
        byte[] iv;
        byte[] key;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) parameters;
            iv = ivParam.getIV().clone();
            KeyParameter params = (KeyParameter) ivParam.getParameters();
            // if null it's an IV changed only.
            if (params != null)
            {
                key = params.getKey();
            }
            else
            {
                throw PacketCipherException.from(new IllegalArgumentException("CBC cipher unitialized"));
            }
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CBC"));
        }
        int outLen = output != null ? output.length : 0;
        int result;
        try
        {
            result = processPacket(encryption, key, key.length, iv, iv.length, input, inOff, len, output, outOff,
                    outLen);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        return result;
    }

    static native int getOutputSize(boolean encryption, int len);

    static native int processPacket(boolean encryption, byte[] key, int keyLen, byte[] nonce, int nonLen, byte[] in,
                                    int inOff, int inLen, byte[] out, int outOff, int outLen);

    @Override
    public String toString()
    {
        return "CBC-PS[Native](AES[Native])";
    }
}
