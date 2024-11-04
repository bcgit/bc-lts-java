package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public interface AESCTRModePacketCipher
    extends PacketCipher
{
    default void checkParameters(CipherParameters parameters)
    {
        int ivLen;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            ivLen = ivParam.getIV().length;
            if (16 < ivLen)
            {
                throw new IllegalArgumentException(ExceptionMessages.CTR16_IV_TOO_LONG);
            }
            //int maxCounterSize = Math.min(8, BLOCK_SIZE >> 1);
            if (16 - ivLen > 8) // 8 is the maxCounterSize
            {
                throw new IllegalArgumentException(ExceptionMessages.CTR16_IV_TOO_SHORT);
            }
            KeyParameter keyParameter = (KeyParameter)ivParam.getParameters();
            if (keyParameter == null)
            {
                throw new IllegalStateException(ExceptionMessages.CTR_CIPHER_UNITIALIZED);
            }
            int keyLen = keyParameter.getKeyLength();
            if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
            }
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CTR_INVALID_PARAMETER);
        }
    }
}
