package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.modes.GCMSIVModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

public class AESNativeGCMSIV
    implements GCMSIVModeCipher
{
    private GCMSIVRefWrapper refWrapper;
    private byte[] keptMac;

    /**
     * The encryptedDataStream
     */
    private GCMSIVCache theEncData;

    /**
     * Are we encrypting?
     */
    private boolean forEncryption;

    /**
     * The initialAEAD.
     */
    private byte[] theInitialAEAD;

    /**
     * The nonce.
     */
    private byte[] theNonce;
    private boolean initialised = false;

    private byte[] macBlock = new byte[macSize];
    private static int macSize = 16;

    private byte[] lastKey;

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

    @Override
    public void init(boolean forEncryption, CipherParameters cipherParameters)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        keptMac = null;

        /* Set defaults */
        byte[] myInitialAEAD = null;
        byte[] myNonce;
        KeyParameter myKey;

        /* Access parameters */
        if (cipherParameters instanceof AEADParameters)
        {
            final AEADParameters myAEAD = (AEADParameters)cipherParameters;
            myInitialAEAD = myAEAD.getAssociatedText();
            myNonce = myAEAD.getNonce();
            myKey = myAEAD.getKey();
        }
        else if (cipherParameters instanceof ParametersWithIV)
        {
            final ParametersWithIV myParms = (ParametersWithIV)cipherParameters;
            myNonce = myParms.getIV();
            myKey = (KeyParameter)myParms.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
        }

        /* Reset details */
        theInitialAEAD = myInitialAEAD;
        theNonce = myNonce;
        lastKey = myKey.getKey();
        switch (lastKey.length)
        {
        case 16:
        case 24:
        case 32:
            break;
        default:
            throw new IllegalStateException(ExceptionMessage.AES_KEY_LENGTH);
        }

        initRef(lastKey.length);


        initNative(
            refWrapper.getReference(),
            forEncryption, lastKey,
            theNonce, theInitialAEAD);
        initialised = true;
        resetStreams();
    }

    private void initRef(int keySize)
    {
        refWrapper = new GCMSIVRefWrapper(makeInstance(keySize, forEncryption));
    }

    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM-SIV";
    }

    @Override
    public void processAADByte(byte in)
    {
        processAADByte(refWrapper.getReference(), in);
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (refWrapper == null)
        {
            throw new IllegalStateException(ExceptionMessage.GCM_SIV_UNINITIALIZED);
        }

        processAADBytes(refWrapper.getReference(), in, inOff, len);
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        if (refWrapper == null)
        {
            throw new IllegalStateException(ExceptionMessage.GCM_SIV_UNINITIALIZED);
        }
        theEncData.write(in);
        return processByte(refWrapper.getReference(), in, out, outOff, theEncData.size());
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (refWrapper == null)
        {
            throw new IllegalStateException(ExceptionMessage.GCM_SIV_UNINITIALIZED);
        }
        theEncData.write(in, inOff, len);
        return processBytes(refWrapper.getReference(), in, inOff, len, out, outOff, theEncData.size());
    }

    @Override
    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            if (forEncryption)
            {
                throw new IllegalStateException("GCM cipher cannot be reused for encryption");
            }
            throw new IllegalStateException("GCM cipher needs to be initialised");
        }
        byte[] mySrc = theEncData.getBuffer();
        int len = doFinal(refWrapper.getReference(), out, outOff, mySrc, theEncData.size());
        //resetKeepMac
        keptMac = getMac();
        reset(refWrapper.getReference());
        initialised = false;
        return len;
    }

    @Override
    public byte[] getMac()
    {
        if (keptMac != null)
        {
            return Arrays.clone(keptMac);
        }
        return getMac(refWrapper.getReference());
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return getUpdateOutputSize(refWrapper.getReference(), len, theEncData.size());
    }

    @Override
    public int getOutputSize(int len)
    {
        return getOutputSize(refWrapper.getReference(), len);
    }

    private void resetStreams()
    {
        theEncData = new GCMSIVCache();
    }

    @Override
    public void reset()
    {
        if (refWrapper == null)
        {
            // deal with reset being called before init.
            return;
        }

        reset(refWrapper.getReference());
        initialised = false;
    }

    private static class GCMSIVRefWrapper
        extends NativeReference
    {
        public GCMSIVRefWrapper(long reference)
        {
            super(reference, "GCM-SIV");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }

    }

    private static class Disposer
        extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            AESNativeGCMSIV.dispose(reference);
        }
    }

    private native void reset(long ref);

    static native void initNative(
        long reference,
        boolean forEncryption,
        byte[] keyParam,
        byte[] nonce,
        byte[] initialAssociatedText);

    static native long makeInstance(int keySize, boolean forEncryption);

    static native void dispose(long nativeRef);

    private static native void processAADByte(long ref, byte in);

    private static native void processAADBytes(long ref, byte[] in, int inOff, int len);

    private static native int processByte(long ref, byte in, byte[] out, int outOff, int theEndDataSize);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff, int theEndDataSize);

    private static native int doFinal(long ref, byte[] out, int outOff, byte[] theEndData, int theEndDataSize);

    private static native int getUpdateOutputSize(long ref, int len, int streamLen);

    private static native int getOutputSize(long ref, int len);

    public static native byte[] getMac(long ref);

    /**
     * GCMSIVCache.
     */
    private static class GCMSIVCache
        extends ByteArrayOutputStream
    {
        /**
         * Constructor.
         */
        GCMSIVCache()
        {
        }

        /**
         * Obtain the buffer.
         *
         * @return the buffer
         */
        byte[] getBuffer()
        {
            return this.buf;
        }

        /**
         * Clear the buffer.
         */
        void clearBuffer()
        {
            Arrays.fill(getBuffer(), (byte)0);
        }
    }

}
