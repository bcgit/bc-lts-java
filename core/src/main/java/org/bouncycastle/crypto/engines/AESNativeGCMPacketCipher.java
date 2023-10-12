package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESGCMModePacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

import javax.security.auth.DestroyFailedException;

public class AESNativeGCMPacketCipher
    extends AESPacketCipherEngine
    implements AESGCMModePacketCipher
{
    private byte[] lastKey;
    private byte[] lastNonce;
    private boolean destroyed;

    public AESNativeGCMPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        int macSize = checkParameters(parameters);
        return getOutputSize(encryption, len, macSize);
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters params, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
        int macSize;
        byte[] nonce;
        byte[] initialAssociatedText;
        byte[] key;
        try
        {
            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters)params;
                nonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();

                int macSizeBits = param.getMacSize();
                if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
                {
                    throw new IllegalArgumentException(ExceptionMessages.GCM_INVALID_MAC_SIZE + macSizeBits);
                }

                macSize = macSizeBits >> 3;

                key = param.getKey().getKey();

                // This only works if you use the same instance of packet cipher
                // It matches the existing behavior of the normal GCM implementation
                if (encryption && Arrays.areEqual(key, lastKey) && Arrays.areEqual(nonce, lastNonce))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }

                lastKey = Arrays.clone(key);
                lastNonce = Arrays.clone(nonce);
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV)params;
                nonce = param.getIV().clone();
                initialAssociatedText = null;
                macSize = 16;

                key = ((KeyParameter)param.getParameters()).getKey();

                // This only works if you use the same instance of packet cipher
                // It matches the existing behavior of the normal GCM implementation
                if (encryption && Arrays.areEqual(key, lastKey) && Arrays.areEqual(nonce, lastNonce))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }

                lastKey = Arrays.clone(key);
                lastNonce = Arrays.clone(nonce);

            }
            else
            {
                throw new IllegalArgumentException(ExceptionMessages.GCM_INVALID_PARAMETER);
            }
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }

        int iatLen = initialAssociatedText != null ? initialAssociatedText.length : 0;
        int outLen = output != null ? output.length : 0;
        int result;
        try
        {
            result = processPacket(encryption, key, key.length, nonce, nonce.length, initialAssociatedText, iatLen,
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
                                    int aadLen, int macSize, byte[] in, int inOff, int inLen, byte[] out, int outOff,
                                    int outLen);

    @Override
    public String toString()
    {
        return "GCM-PS[Native](AES[Native])";
    }

    @Override
    public void destroy()
        throws DestroyFailedException
    {
        Arrays.clear(lastKey);
        Arrays.clear(lastNonce);
        lastKey = null;
        lastNonce = null;
        destroyed = true;
    }

    @Override
    public boolean isDestroyed()
    {
        return destroyed;
    }

}
