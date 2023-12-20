package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public interface AESCBCModePacketCipher
        extends PacketCipher
{

    default void checkParameters(CipherParameters parameters) throws PacketCipherException
    {
        KeyParameter kp = null;
        if (parameters instanceof KeyParameter)
        {
            kp = (KeyParameter) parameters;
        }
        else if (parameters instanceof ParametersWithIV)
        {
            kp = (KeyParameter) ((ParametersWithIV) parameters).getParameters();

            //
            // Test the IV as we have it.
            //
            if (((ParametersWithIV) parameters).getIV().length != AESPacketCipher.BLOCK_SIZE)
            {
                throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.IV_LENGTH_16));
            }
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INVALID_PARAM_TYPE));
        }

        AESPacketCipher.checkKeyLength(kp.getKeyLength());
    }
}
