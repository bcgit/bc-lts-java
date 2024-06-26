package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.AESCTRModePacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESNativeCTRPacketCipher
        implements AESCTRModePacketCipher
{


    public AESNativeCTRPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        checkParameters(parameters);
        return getOutputSize(len);
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
            iv = Arrays.clone(ivParam.getIV());
            KeyParameter keyParameter = (KeyParameter) ivParam.getParameters();
            if (keyParameter == null)
            {
                throw PacketCipherException.from(new IllegalStateException(ExceptionMessages.CTR_CIPHER_UNITIALIZED));
            }
            key = keyParameter.getKey();
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CTR_INVALID_PARAMETER);
        }
        int result;
        try
        {
            result = processPacket(encryption, key, iv, input, inOff, len, output, outOff, output.length - outOff);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        return result;
    }

    static native int getOutputSize(int len);

    static native int processPacket(boolean encryption, byte[] key, byte[] nonce, byte[] in, int inOff, int inLen,
                                    byte[] out, int outOff, int outLen);

    @Override
    public String toString()
    {
        return "CTR-PS[Native](AES[Native])";
    }
}
