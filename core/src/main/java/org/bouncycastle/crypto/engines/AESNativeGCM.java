package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeReference;

public class AESNativeGCM
    implements AEADBlockCipher, GCMCipher
{

    private GCMRefWrapper refWrapper;
    private int macSizeBits = 0;

    private byte[] lastNonce;

    private byte[] lastKey;

    private boolean doFinalCalled = false;

    private boolean forEncryption = false;

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        return VoidBlockCipher.instance;
    }


    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        byte[] key = null;
        byte[] nonce = null;
        byte[] initialAssociatedText = null;

        this.forEncryption = forEncryption;

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            nonce = param.getNonce();

            initialAssociatedText = param.getAssociatedText();

            macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            if (param.getKey() != null)
            {
                key = param.getKey().getKey();
            }
            else if (!forEncryption)
            {
                // Decryption so reuse last key
                key = Arrays.clone(lastKey);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;
            nonce = param.getIV();
            macSizeBits = 128;
            if (param.getParameters() != null)
            {
                key = ((KeyParameter)param.getParameters()).getKey();
            }
            else if (!forEncryption)
            {
                // Decryption so reuse last key
                key = Arrays.clone(lastKey);
            }
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        if (forEncryption)
        {
            if (lastNonce != null && Arrays.areEqual(lastNonce, nonce))
            {
                if (key == null)
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
                if (lastKey != null && Arrays.areEqual(lastKey, key))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
            }
        }

        initRef(key.length);
        initNative(refWrapper.getReference(), forEncryption, key, nonce, initialAssociatedText, macSizeBits);

        lastNonce = Arrays.clone(nonce);
        lastKey = Arrays.clone(key);

        doFinalCalled = false;
    }


    private void initRef(int keySize)
    {
        if (refWrapper != null)
        {
            refWrapper.dispose();
        }
        refWrapper = new GCMRefWrapper(makeInstance(keySize));
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM";
    }

    @Override
    public void processAADByte(byte in)
    {
        processAADByte(refWrapper.getReference(), in);
    }


    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (inOff + len > in.length)
        {
            throw new IllegalArgumentException("inOff + len past end of data");
        }
        processAADBytes(refWrapper.getReference(), in, inOff, len);
    }


    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        if (outOff > out.length)
        {
            throw new IllegalArgumentException("offset past end of output array");
        }

        return processByte(refWrapper.getReference(), in, out, outOff);
    }


    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (inOff + len > in.length)
        {
            throw new IllegalStateException("inOdd + len is past end of input");
        }

        if (outOff > out.length)
        {
            throw new IllegalArgumentException("offset past end of output array");
        }

        return processBytes(refWrapper.getReference(), in, inOff, len, out, outOff);
    }


    @Override
    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {

        if (forEncryption)
        {
            if (doFinalCalled)
            {
                throw new IllegalStateException("GCM cipher cannot be reused for encryption");
            }
            else
            {
                doFinalCalled = true;
            }
        }


        if (outOff > out.length)
        {
            throw new IllegalArgumentException("offset past end of output array");
        }

        return doFinal(refWrapper.getReference(), out, outOff);
    }


    @Override
    public byte[] getMac()
    {
        return getMac(refWrapper.getReference());
    }


    @Override
    public int getUpdateOutputSize(int len)
    {
        return getUpdateOutputSize(refWrapper.getReference(), len);
    }


    @Override
    public int getOutputSize(int len)
    {
        return getOutputSize(refWrapper.getReference(), len);
    }


    @Override
    public void reset()
    {
        if (refWrapper == null || refWrapper.isDisposed())
        {
            // deal with reset being called before init.
            return;
        }

        reset(refWrapper.getReference());
    }

    private native void reset(long ref);


    private static native void initNative(
        long reference,
        boolean forEncryption,
        byte[] keyParam,
        byte[] nonce,
        byte[] initialAssociatedText,
        int macSizeBits);

    private static native long makeInstance(int keySize);

    private static native void dispose(long nativeRef);

    private static native void processAADByte(long ref, byte in);

    private static native void processAADBytes(long ref, byte[] in, int inOff, int len);

    private static native int processByte(long ref, byte in, byte[] out, int outOff)
        throws DataLengthException;

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException;

    private static native int doFinal(long ref, byte[] out, int outOff);

    private static native int getUpdateOutputSize(long ref, int len);

    private static native int getOutputSize(long ref, int len);

    public static native byte[] getMac(long ref);


    private static class GCMRefWrapper
        extends NativeReference
    {
        public GCMRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        protected void destroy(long reference)
        {
            AESNativeGCM.dispose(reference);
        }
    }


    static class VoidBlockCipher
        implements BlockCipher
    {

        private static VoidBlockCipher instance = new VoidBlockCipher();

        @Override
        public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
        {
            throw new IllegalStateException("void cipher cannot be initialized");
        }

        @Override
        public String getAlgorithmName()
        {
            return "VOID";
        }

        @Override
        public int getBlockSize()
        {
            return 0;
        }

        @Override
        public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
        {
            throw new IllegalStateException("void cipher cannot process blocks");
        }

        @Override
        public void reset()
        {

        }
    }
}
