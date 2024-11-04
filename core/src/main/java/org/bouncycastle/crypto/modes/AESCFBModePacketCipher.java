package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public interface AESCFBModePacketCipher
    extends PacketCipher
{
    default void checkCFBParameter(CipherParameters parameters)
    {
        if (parameters instanceof ParametersWithIV)
        {
            KeyParameter param = (KeyParameter)((ParametersWithIV)parameters).getParameters();
            if (param == null)
            {
                throw new IllegalArgumentException(ExceptionMessages.CFB_CIPHER_UNITIALIZED);
            }
            int keyLen = param.getKeyLength();
            if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
            }
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CFB_CIPHER_UNITIALIZED);
        }
    }
}
