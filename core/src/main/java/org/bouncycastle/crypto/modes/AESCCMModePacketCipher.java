package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


public interface AESCCMModePacketCipher
    extends PacketCipher
{
    default int getMacSize(boolean encryption, CipherParameters params)
    {
        int macSize;
        byte[] nonce;
        KeyParameter keyParam;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
            macSize = getCCMMacSize(encryption, param.getMacSize());
            keyParam = param.getKey();
            nonce = param.getNonce();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;
            macSize = 8;
            keyParam = (KeyParameter)param.getParameters();
            nonce = param.getIV();
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CCM_INVALID_PARAMETER);
        }
        if (nonce == null || nonce.length < 7 || nonce.length > 13)
        {
            throw new IllegalArgumentException(ExceptionMessages.CCM_IV_SIZE);
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
            throw new IllegalArgumentException(ExceptionMessages.CCM_CIPHER_UNITIALIZED);
        }
        return macSize;
    }

    default int getCCMMacSize(boolean forEncryption, int requestedMacBits)
    {
        if (forEncryption && (requestedMacBits < 32 || requestedMacBits > 128 || 0 != (requestedMacBits & 15)))
        {
            throw new IllegalArgumentException(ExceptionMessages.CCM_MAC_SIZE);
        }
        return requestedMacBits >>> 3;
    }
}
