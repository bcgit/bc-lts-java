package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public interface AESGCMSIVModePacketCipher
    extends PacketCipher
{
    /**
     * The nonce length.
     */
    int NONCELEN = 12;
    default void checkParameters(CipherParameters parameters)
    {
        byte[] myNonce;
        KeyParameter myKey;
        if (parameters instanceof AEADParameters)
        {
            final AEADParameters myAEAD = (AEADParameters)parameters;
            myNonce = myAEAD.getNonce();
            myKey = myAEAD.getKey();
        }
        else if (parameters instanceof ParametersWithIV)
        {
            final ParametersWithIV myParms = (ParametersWithIV)parameters;
            myNonce = Arrays.clone(myParms.getIV());
            myKey = (KeyParameter)myParms.getParameters();
        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.GCM_SIV_INVALID_PARAMETER);
        }
        /* Check nonceSize */
        if (myNonce == null || myNonce.length != NONCELEN)
        {
            throw new IllegalArgumentException(ExceptionMessages.GCM_SIV_IV_SIZE);
        }

        /* Check keysize */
        if (myKey == null || (myKey.getKeyLength() != 16 && myKey.getKeyLength() != 32))
        {
            throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
        }
    }
}
