package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.security.auth.Destroyable;

public interface AESGCMModePacketCipher
    extends PacketCipher, Destroyable
{
    default int checkParameters(CipherParameters params)
    {
        byte[] newNonce;
        KeyParameter keyParam;
        int macSize;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
            newNonce = param.getNonce();
            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessages.GCM_INVALID_MAC_SIZE + macSizeBits);
            }
            keyParam = param.getKey();
            macSize = macSizeBits >> 3;
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;
            newNonce = param.getIV();
            keyParam = (KeyParameter)param.getParameters();
            macSize = 16;
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.GCM_INVALID_PARAMETER);
        }
        if (newNonce == null || newNonce.length < 12)
        {
            throw new IllegalArgumentException(ExceptionMessages.GCM_IV_TOO_SHORT);
        }
        if (keyParam != null)
        {
            int keyLen = keyParam.getKeyLength();
            if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
            }
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.GCM_INVALID_PARAMETER);
        }
        return macSize;
    }
}
