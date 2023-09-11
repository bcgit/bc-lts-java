package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.AESCTRModePacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESNativeCTRPacketCipher
    extends AESPacketCipherEngine
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
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        byte[] iv;
        byte[] key;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            iv = Arrays.clone(ivParam.getIV());
            KeyParameter keyParameter = (KeyParameter)ivParam.getParameters();
            if (keyParameter == null)
            {
                throw PacketCipherException.from(new IllegalStateException(ExceptionMessage.CTR_CIPHER_UNITIALIZED));
            }
            key = keyParameter.getKey();
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessage.CTR_INVALID_PARAMETER);
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
        return "CTR-PS[Native](AES[Native])";
    }
}
