package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESCCMModePacketCipher;
import org.bouncycastle.crypto.modes.AESCCMPacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESNativeCCMPacketCipher
    implements PacketCipher, AESCCMModePacketCipher
{
    public static AESCCMModePacketCipher newInstance()
    {
        return new AESNativeCCMPacketCipher();
    }

    private AESNativeCCMPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters params, int len)
    {
        int macSize;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
            macSize = getMacSize(encryption, param.getMacSize());
        }
        else if (params instanceof ParametersWithIV)
        {
            macSize = 8;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to CCM: " + params.getClass().getName());
        }
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
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
            try
            {
                macSize = getMacSize(forEncryption, param.getMacSize());
            }
            catch (IllegalArgumentException e)
            {
                throw PacketCipherException.from(e);
            }
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
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CCM"));
        }
        if (keyParam != null)
        {
            key = keyParam.getKey();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("CCM cipher unitialized."));
        }
        int iatLen = initialAssociatedText != null ? initialAssociatedText.length : 0;
        int outLen = output != null ? output.length : 0;
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

    private int getMacSize(boolean forEncryption, int requestedMacBits)
    {
        if (forEncryption && (requestedMacBits < 32 || requestedMacBits > 128 || 0 != (requestedMacBits & 15)))
        {
            throw new IllegalArgumentException("tag length in octets must be one of {4,6,8,10,12,14,16}");
        }

        return requestedMacBits >>> 3;
    }
}
