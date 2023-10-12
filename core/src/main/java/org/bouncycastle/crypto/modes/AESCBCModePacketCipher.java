package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public interface AESCBCModePacketCipher
    extends PacketCipher
{
    default void checkParameters(CipherParameters parameters)
    {
        KeyParameter params;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            if (ivParam.getIV().length != 16)
            {
                throw new IllegalArgumentException(ExceptionMessages.CBC_IV_LENGTH);
            }
            params = (KeyParameter)ivParam.getParameters();
        }
        else
        {
            params = (KeyParameter)parameters;
        }
        if (params != null)
        {
            int keyLen = params.getKeyLength();
            if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
            }
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CBC_CIPHER_UNITIALIZED);
        }
    }
}
