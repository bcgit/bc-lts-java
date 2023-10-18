package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.AESCCMModePacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESNativeCCMPacketCipher
    extends AESPacketCipherEngine
    implements PacketCipher, AESCCMModePacketCipher
{
    public AESNativeCCMPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters params, int len)
    {
        int macSize = getMacSize(encryption, params);
        return getOutputSize(encryption, len, macSize);
    }


    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        int macSize;
        byte[] nonce;
        byte[] initialAssociatedText;
        byte[] key;
        KeyParameter keyParam;
        try
        {
            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters)params;
                macSize = getCCMMacSize(forEncryption, param.getMacSize());
                nonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();
                keyParam = param.getKey();
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV)params;
                macSize = 8;
                nonce = param.getIV();
                initialAssociatedText = null;
                keyParam = (KeyParameter)param.getParameters();
            }
            else
            {
                throw new IllegalArgumentException(ExceptionMessages.CCM_INVALID_PARAMETER);
            }
            checkKeyLength(keyParam, ExceptionMessages.CCM_CIPHER_UNITIALIZED);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        key = keyParam.getKey();
        return processAEADPacketCipher(forEncryption, input, inOff, len, output, outOff, initialAssociatedText, key, nonce, macSize);
    }

    private static int processAEADPacketCipher(boolean forEncryption, byte[] input, int inOff, int len, byte[] output, int outOff, byte[] initialAssociatedText, byte[] key, byte[] nonce, int macSize)
        throws PacketCipherException
    {
        int iatLen = initialAssociatedText != null ? initialAssociatedText.length : 0;
        int outLen = output != null ? output.length-outOff : 0;
        int result;
        try
        {
            result = processPacket(forEncryption, key, key.length, nonce, nonce.length, initialAssociatedText, iatLen,
                macSize, input, inOff, len, output, outOff, outLen);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        return result;
    }

    static native int getOutputSize(boolean encryption, int len, int macSize);

    static native int processPacket(boolean encryption, byte[] key, int keyLen, byte[] nonce, int nonLen, byte[] aad,
                                    int aadLen, int macSize, byte[] in, int inOff, int inLen, byte[] out, int outOff, int outLen);

    @Override
    public String toString()
    {
        return "CCM-PS[Native](AES[Native])";
    }
}
