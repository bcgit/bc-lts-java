package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.GCMSIVModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.io.ByteArrayOutputStream;
import java.lang.ref.Reference;

public class AESNativeGCMSIV
        implements GCMSIVModeCipher
{
    private GCMSIVRefWrapper refWrapper;
    private byte[] keptMac;

    /**
     * The encryptedDataStream
     */
    private final GCMSIVCache theEncData = new GCMSIVCache();

    /**
     * Are we encrypting?
     */
    private boolean forEncryption;


    /**
     * The nonce.
     */
    private byte[] theNonce;
    private byte[] theInitialAEAD;


    @Override
    public BlockCipher getUnderlyingCipher()
    {
        try
        {
            BlockCipher engine = AESEngine.newInstance();
            if (refWrapper != null && refWrapper.key != null)
            {
                engine.init(true, new KeyParameter(refWrapper.key));
            }
            return engine;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public void init(boolean forEncryption, CipherParameters cipherParameters)
            throws IllegalArgumentException
    {
        try
        {
            this.forEncryption = forEncryption;
            keptMac = null;
            theEncData.reset();

            /* Set defaults */
            byte[] myInitialAEAD = null;
            byte[] myNonce;
            KeyParameter myKey;

            /* Access parameters */
            if (cipherParameters instanceof AEADParameters)
            {
                final AEADParameters myAEAD = (AEADParameters) cipherParameters;
                myInitialAEAD = myAEAD.getAssociatedText();
                myNonce = myAEAD.getNonce();
                myKey = myAEAD.getKey();
            }
            else if (cipherParameters instanceof ParametersWithIV)
            {
                final ParametersWithIV myParms = (ParametersWithIV) cipherParameters;
                myNonce = myParms.getIV();
                myKey = (KeyParameter) myParms.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
            }

            /* Reset details */
            /**
             * The initialAEAD.
             */
            theInitialAEAD = myInitialAEAD;
            theNonce = myNonce;
            byte[] keyBytes = myKey.getKey();
            switch (keyBytes.length)
            {
                case 16:
                case 24:
                case 32:
                    break;
                default:
                    throw new IllegalStateException(ExceptionMessages.AES_KEY_LENGTH);
            }

            initRef(keyBytes);


            initNative(
                    refWrapper.getReference(),
                    forEncryption, refWrapper.key,
                    theNonce, theInitialAEAD);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private void initRef(byte[] key)
    {
        refWrapper = new GCMSIVRefWrapper(makeInstance(), key);
    }

    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM-SIV";
    }

    @Override
    public void processAADByte(byte in)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            processAADByte(refWrapper.getReference(), in);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            processAADBytes(refWrapper.getReference(), in, inOff, len);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
            throws DataLengthException
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            theEncData.write(in);
            return 0;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            theEncData.write(in, inOff, len);
            return 0;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int doFinal(byte[] out, int outOff)
            throws IllegalStateException, InvalidCipherTextException
    {

        try
        {
            int len = doFinal(refWrapper.getReference(), theEncData.getBuffer(), theEncData.size(), out, outOff);
            //resetKeepMac
            keptMac = getMac();
            reset();
            return len;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public byte[] getMac()
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }

            if (keptMac != null)
            {
                return Arrays.clone(keptMac);
            }
            return getMac(refWrapper.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            return getUpdateOutputSize(refWrapper.getReference(), len, theEncData.size());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int getOutputSize(int len)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException(ExceptionMessages.GCM_SIV_UNINITIALIZED);
            }
            return getOutputSize(refWrapper.getReference(), len);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public void reset()
    {
        try
        {
            theEncData.clearBuffer();
            if (refWrapper == null)
            {
                // deal with reset being called before init.
                return;
            }
            reset(refWrapper.getReference());
            initNative(
                    refWrapper.getReference(),
                    forEncryption, refWrapper.key,
                    theNonce, theInitialAEAD);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    public String toString()
    {
        try
        {
            if (refWrapper != null && refWrapper.key != null)
            {
                return "GCMSIV[Native](AES[Native](" + (refWrapper.key.length * 8) + "))";
            }
            return "GCMSIV[Native](AES[Native](not initialized))";
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private static class GCMSIVRefWrapper
            extends NativeReference
    {
        private final byte[] key;

        public GCMSIVRefWrapper(long reference, byte[] key)
        {
            super(reference, "GCM-SIV");
            this.key = key;
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference, key);
        }

    }

    private static class Disposer
            extends NativeDisposer
    {
        private final byte[] key;

        Disposer(long ref, byte[] key)
        {
            super(ref);
            this.key = key;
        }

        @Override
        protected void dispose(long reference)
        {
            Arrays.clear(key);
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

    static native long makeInstance();

    static native void dispose(long nativeRef);

    static native void processAADByte(long ref, byte in);

    static native void processAADBytes(long ref, byte[] in, int inOff, int len);

    static native int doFinal(long ref, byte[] input, int inputLen, byte[] out, int outOff);

    static native int getUpdateOutputSize(long ref, int len, int streamLen);

    static native int getOutputSize(long ref, int len);

    static native byte[] getMac(long ref);

    /**
     * Test method, you have ABSOLUTELY no reason to call this in normal use.
     * max_dl is the maximum amount of data the implementation will process.
     */
    static native void test_set_max_dl(long ref, long value);


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
            Arrays.fill(getBuffer(), (byte) 0);
            reset();
        }
    }

}
