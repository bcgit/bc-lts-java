package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESCFBModePacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESNativeCFBPacketCipher
    extends AESPacketCipherEngine
    implements AESCFBModePacketCipher
{


    public AESNativeCFBPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        checkCFBParameter(parameters);
        return getOutputSize(len);
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
                throw new IllegalArgumentException(ExceptionMessages.CFB_CIPHER_UNITIALIZED);
            }
            iv = ivParam.getIV().clone();
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CFB_CIPHER_UNITIALIZED);
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

    static native int getOutputSize(int len);

    static native int processPacket(boolean encryption, byte[] key, int keyLen, byte[] nonce, byte[] in, int inOff, int inLen, byte[] out, int outOff);

    @Override
    public String toString()
    {
        return "CFB-PS[Native](AES[Native])";
    }
}
