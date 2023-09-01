package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.AESGCMModePacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.Disposable;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class AESNativeGCMPacketCipher
        extends AESPacketCipherEngine
        implements AESGCMModePacketCipher, Destroyable
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
        int macSize;
        if (parameters instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) parameters;
            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            macSize = macSizeBits >> 3;

        }
        else if (parameters instanceof ParametersWithIV)
        {
            macSize = 16;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }
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
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) params;
            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
            {
                throw PacketCipherException.from(new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits));
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
            ParametersWithIV param = (ParametersWithIV) params;
            nonce = param.getIV().clone();
            initialAssociatedText = null;
            macSize = 16;

            key = ((KeyParameter) param.getParameters()).getKey();

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
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to GCM"));
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
        return "GCM Packet Cipher (Native)";
    }

    @Override
    public void destroy() throws DestroyFailedException
    {
        Arrays.clear(lastKey);
        Arrays.clear(lastNonce);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed()
    {
        return destroyed;
    }

}
