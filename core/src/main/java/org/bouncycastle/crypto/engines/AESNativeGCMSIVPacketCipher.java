package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESGCMSIVModePacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESNativeGCMSIVPacketCipher
    extends AESPacketCipherEngine
    implements AESGCMSIVModePacketCipher
{
    public static AESGCMSIVModePacketCipher newInstance()
    {
        return new AESNativeGCMSIVPacketCipher();
    }

    private AESNativeGCMSIVPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        return getOutputSize(encryption, len);
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters params, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        byte[] nonce;
        byte[] initialAssociatedText;
        byte[] key;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();
            key = param.getKey().getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;
            nonce = param.getIV().clone();
            initialAssociatedText = null;
            key = ((KeyParameter)param.getParameters()).getKey();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to GCM-SIV"));
        }
        int iatLen = initialAssociatedText != null ? initialAssociatedText.length : 0;
        int outLen = output != null ? output.length : 0;
        int result;
        try
        {
            result = processPacket(encryption, key, key.length, nonce, initialAssociatedText, iatLen,
                 input, inOff, len, output, outOff, outLen);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        return result;
    }

    static native int getOutputSize(boolean encryption, int len);

    static native int processPacket(boolean encryption, byte[] key, int keyLen, byte[] nonce,  byte[] aad,
                                    int aadLen,  byte[] in, int inOff, int inLen, byte[] out, int outOff, int outLen);
    @Override
    public String toString()
    {
        return "GCM-SIV Packet Cipher (Native)";
    }
}
