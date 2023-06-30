package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class AESNativeCCM
        implements CCMModeCipher
{
    private CCMRefWrapper refWrapper;
    private byte[] lastKey;
    private boolean forEncryption = false;
    private boolean initialised = false;

    private final ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private final ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        BlockCipher engine = AESEngine.newInstance();
        if (lastKey != null)
        {
            engine.init(true, new KeyParameter(lastKey));
        }
        return engine;
    }


    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        CipherParameters cipherParameters;
        KeyParameter keyParam = null;

        byte[] nonce;
        byte[] initialAssociatedText;
        int macSize;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) params;

            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();
            macSize = getMacSize(forEncryption, param.getMacSize());
            cipherParameters = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV) params;

            nonce = param.getIV();
            initialAssociatedText = null;
            macSize = getMacSize(forEncryption, 64);
            cipherParameters = param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to CCM");
        }

        // NOTE: Very basic support for key re-use, but no performance gain from it
        if (cipherParameters != null)
        {
            keyParam = (KeyParameter) cipherParameters;
        }

        if (keyParam != null)
        {
            lastKey = keyParam.getKey();
            if (lastKey == null)
            {
                throw new IllegalArgumentException("key was null");
            }
            initRef(lastKey.length);
        }

        int iatLen = initialAssociatedText != null ? initialAssociatedText.length : 0;
        initNative(
                refWrapper.getReference(),
                forEncryption, lastKey,
                nonce, initialAssociatedText, iatLen, macSize * 8);
        reset();
        initialised = true;
    }


    private void initRef(int keySize)
    {
        refWrapper = new CCMRefWrapper(makeInstance());
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CCM";
    }

    @Override
    public void processAADByte(byte in)
    {
        associatedText.write(in);
    }


    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (inOff < 0)
        {
            throw new IllegalArgumentException("offset is negative");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("len is negative");
        }
        if (in.length < inOff + len)
        {
            throw new IllegalArgumentException("array too short for offset + len");
        }
        associatedText.write(in, inOff, len);
    }


    @Override
    public int processByte(byte in, byte[] out, int outOff)
            throws DataLengthException
    {
        if (outOff < 0)
        {
            throw new IllegalArgumentException("offset is negative");
        }

        if (out != null && out.length < outOff)
        {
            throw new DataLengthException("offset past end");
        }
        data.write(in);
        return 0;
    }


    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {
        if (inOff < 0 || outOff < 0)
        {
            throw new IllegalArgumentException("offset is negative");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("len is negative");
        }
        if (in == null)
        {
            throw new NullPointerException("input was null");
        }
        if (in.length < (inOff + len))
        {
            throw new DataLengthException("array too short for offset + len");
        }
        data.write(in, inOff, len);

        return 0;
    }


    @Override
    public int doFinal(byte[] out, int outOff)
            throws IllegalStateException, InvalidCipherTextException
    {
        int len;
        try
        {
            checkStatus();
            if (out == null)
            {
                throw new NullPointerException("output was null");
            }
            if (outOff < 0)
            {
                throw new IllegalArgumentException("offset is negative");
            }
            byte[] input = data.toByteArray();
            byte[] aad = associatedText.toByteArray();
            if (getOutputSize(0) > out.length - outOff)
            {
                throw new OutputLengthException("output buffer too short");
            }
            len = processPacket(refWrapper.getReference(), input, 0, input.length, aad, 0, aad.length, out, outOff);
            resetKeepMac();
            //
            // BlockCipherTest, testing ShortTagException.
            //
        }
        catch (IllegalStateException e)
        {
            reset();
            throw e;
        }

        return len;
    }


    @Override
    public byte[] getMac()
    {
        return getMac(refWrapper.getReference());
    }


    @Override
    public int getUpdateOutputSize(int len)
    {
        return 0; // Not relevant in CCM.
    }


    @Override
    public int getOutputSize(int len)
    {
        return getOutputSize(refWrapper.getReference(), len + data.size());
    }


    @Override
    public void reset()
    {
        if (refWrapper == null)
        {
            // deal with reset being called before init.
            return;
        }
        associatedText.reset();
        data.reset();
        reset(refWrapper.getReference(), false);
    }

    private void resetKeepMac()
    {
        if (refWrapper == null)
        {
            // deal with reset being called before init.
            return;
        }
        associatedText.reset();
        data.reset();
        reset(refWrapper.getReference(), true);
    }


    private void checkStatus()
    {
        if (!initialised)
        {
            if (forEncryption)
            {
                throw new IllegalStateException("CCM cipher cannot be reused for encryption");
            }
            throw new IllegalStateException("CCM cipher needs to be initialised");
        }
    }

    private native void reset(long ref, boolean keepMac);

    static native void initNative(
            long reference,
            boolean forEncryption,
            byte[] keyParam,
            byte[] nonce,
            byte[] initialAssociatedText,
            int initialAssociatedTextLen,
            int macSizeBits);

    static native long makeInstance();

    static native void dispose(long nativeRef);


    static native int getOutputSize(long ref, int len);

    static native byte[] getMac(long ref);

    static native int processPacket(long ref, byte[] in, int inOff, int inLen, byte[] aad, int aadOff, int aadlen,
                                    byte[] out, int outOff);

    @Override
    public int processPacket(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
            throws InvalidCipherTextException
    {
        byte[] aad = associatedText.toByteArray();
        int result = processPacket(refWrapper.getReference(), inBuf, inOff, length, aad, 0, aad.length, outBuf, outOff);
        reset();
        return result;
    }

    @Override
    public byte[] processPacket(byte[] input, int inOff, int length)
            throws InvalidCipherTextException
    {
        byte[] out = new byte[getOutputSize(length)];
        processPacket(input, inOff, length, out, 0);
        reset();
        return out;
    }

    private class CCMRefWrapper
            extends NativeReference
    {
        public CCMRefWrapper(long reference)
        {
            super(reference, "CCM");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }

    }


    private class Disposer
            extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            data.reset();
            associatedText.reset();
            AESNativeCCM.dispose(reference);
        }
    }

    @Override
    public String toString()
    {
        if (lastKey != null)
        {
            return "CCM[Native](AES[Native](" + (lastKey.length * 8) + "))";
        }
        return "CCM[Native](AES[Native](not initialized))";
    }


    private int getMacSize(boolean forEncryption, int requestedMacBits)
    {
        if (forEncryption && (requestedMacBits < 32 || requestedMacBits > 128 || 0 != (requestedMacBits & 15)))
        {
            throw new IllegalArgumentException("invalid value for MAC size");
        }

        return requestedMacBits >>> 3;
    }

    private static class ExposedByteArrayOutputStream
            extends ByteArrayOutputStream
    {
        public ExposedByteArrayOutputStream()
        {
            super();
        }

        public byte[] getBuffer()
        {
            return this.buf;
        }
    }
}
