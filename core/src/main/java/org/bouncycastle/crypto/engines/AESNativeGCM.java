package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class AESNativeGCM
        implements GCMModeCipher
{
    private GCMRefWrapper refWrapper;
    private byte[] oldNonce;
    private boolean forEncryption = false;
    private boolean initialised = false;
    private byte[] keptMac = null;


    @Override
    public BlockCipher getUnderlyingCipher()
    {
        synchronized (this)
        {
            BlockCipher engine = AESEngine.newInstance();
            if (refWrapper != null && refWrapper.key != null)
            {
                engine.init(true, new KeyParameter(refWrapper.key));
            }
            return engine;
        }
    }


    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        synchronized (this)
        {
            this.forEncryption = forEncryption;
            KeyParameter keyParam;
            byte[] newNonce = null;
            keptMac = null;
            int macSize;
            byte[] initialAssociatedText;

            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters) params;

                newNonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();

                int macSizeBits = param.getMacSize();
                if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
                {
                    throw new IllegalArgumentException("invalid value for MAC size: " + macSizeBits);
                }

                macSize = macSizeBits;
                keyParam = param.getKey();
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV) params;

                newNonce = param.getIV();
                initialAssociatedText = null;
                macSize = 128;
                keyParam = (KeyParameter) param.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("invalid parameters passed to GCM");
            }

            if (newNonce == null || newNonce.length < 12)
            {
                throw new IllegalArgumentException("IV must be at least 12 bytes");
            }

            byte[] key = null;

            if (forEncryption)
            {
                if (oldNonce != null && Arrays.areEqual(oldNonce, newNonce))
                {
                    if (keyParam == null)
                    {
                        throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                    }

                    if (refWrapper != null && refWrapper.key != null && Arrays.areEqual(refWrapper.key, keyParam.getKey()))
                    {
                        // same nonce, same key
                        throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                    }

                    if (refWrapper != null && refWrapper.key != null)
                    {
                        key = Arrays.clone(refWrapper.key); // Case keyParam is null
                    }
                }
            }

            oldNonce = newNonce;

            if (keyParam != null)
            {
                key = keyParam.getKey();
                switch (key.length)
                {
                    case 16:
                    case 24:
                    case 32:
                        break;
                    default:
                        throw new IllegalStateException("key must be only 16,24,or 32 bytes long.");
                }
            }

            initRef(key);

            initNative(
                    refWrapper.getReference(),
                    forEncryption, key,
                    oldNonce, initialAssociatedText, macSize);


            initialised = true;
        }
    }


    private void initRef(byte[] key)
    {
        refWrapper = new GCMRefWrapper(makeInstance(key.length, forEncryption), key);
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM";
    }

    @Override
    public void processAADByte(byte in)
    {
        synchronized (this)
        {
            processAADByte(refWrapper.getReference(), in);
        }
    }


    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        synchronized (this)
        {
//
            if (refWrapper == null)
            {
                throw new IllegalStateException("GCM is uninitialized");
            }

            processAADBytes(refWrapper.getReference(), in, inOff, len);
        }
    }


    @Override
    public int processByte(byte in, byte[] out, int outOff)
            throws DataLengthException
    {
        synchronized (this)
        {

            if (refWrapper == null)
            {
                throw new IllegalStateException("GCM is uninitialized");
            }

            return processByte(refWrapper.getReference(), in, out, outOff);
        }
    }


    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {
        synchronized (this)
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException("GCM is uninitialized");
            }

            return processBytes(refWrapper.getReference(), in, inOff, len, out, outOff);
        }
    }


    @Override
    public int doFinal(byte[] out, int outOff)
            throws IllegalStateException, InvalidCipherTextException
    {

        synchronized (this)
        {
            checkStatus();


            int len = doFinal(refWrapper.getReference(), out, outOff);

            //
            // BlockCipherTest, testing ShortTagException.
            //

            resetKeepMac();
            return len;
        }
    }


    @Override
    public byte[] getMac()
    {
        synchronized (this)
        {
            if (keptMac != null)
            {
                return Arrays.clone(keptMac);
            }
            return getMac(refWrapper.getReference());
        }
    }


    @Override
    public int getUpdateOutputSize(int len)
    {
        synchronized (this)
        {
            return getUpdateOutputSize(refWrapper.getReference(), len);
        }
    }


    @Override
    public int getOutputSize(int len)
    {
        synchronized (this)
        {
            return getOutputSize(refWrapper.getReference(), len);
        }
    }


    @Override
    public void reset()
    {
        synchronized (this)
        {
            if (refWrapper == null)
            {
                // deal with reset being called before init.
                return;
            }

            reset(refWrapper.getReference());
            if (forEncryption)
            {
                initialised = false;
            }
        }

    }

    private void resetKeepMac()
    {
        synchronized (this)
        {
            if (refWrapper == null)
            {
                // deal with reset being called before init.
                return;
            }

            keptMac = getMac();
            reset(refWrapper.getReference());
            if (forEncryption)
            {
                initialised = false;
            }
        }
    }


    private void checkStatus()
    {
        if (!initialised)
        {
            if (forEncryption)
            {
                throw new IllegalStateException("GCM cipher cannot be reused for encryption");
            }
            throw new IllegalStateException("GCM cipher needs to be initialised");
        }
    }



    @Override
    public String toString()
    {
        synchronized (this)
        {
            if (refWrapper.key != null)
            {
                return "GCM[Native](AES[Native](" + (refWrapper.key.length * 8) + "))";
            }
            return "GCM[Native](AES[Native](not initialized))";
        }
    }

    private static class GCMRefWrapper
            extends NativeReference
    {
        private final byte[] key;

        public GCMRefWrapper(long reference, byte[] key)
        {
            super(reference, "GCM");
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
            AESNativeGCM.dispose(reference);
        }
    }

    private native void reset(long ref);

    static native void initNative(
            long reference,
            boolean forEncryption,
            byte[] keyParam,
            byte[] nonce,
            byte[] initialAssociatedText,
            int macSizeBits);

    static native long makeInstance(int keySize, boolean forEncryption);

    static native void dispose(long nativeRef);

    private static native void processAADByte(long ref, byte in);

    private static native void processAADBytes(long ref, byte[] in, int inOff, int len);

    private static native int processByte(long ref, byte in, byte[] out, int outOff);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff);

    private static native int doFinal(long ref, byte[] out, int outOff);

    private static native int getUpdateOutputSize(long ref, int len);

    private static native int getOutputSize(long ref, int len);

    public static native byte[] getMac(long ref);

    /**
     * Set blocks remaining but only to a lesser value and only if the transformation has processed no data.
     * Functionality limited to within the module only.
     *
     * @param value the step value.
     */
    void setBlocksRemainingDown(long value)
    {
        synchronized (this)
        {
            setBlocksRemainingDown(refWrapper.getReference(), value);
        }
    }

    // Set the blocks remaining, but only to a lesser value.
    // This is intended for testing only and will throw from the native side if the
    // transformation has processed any data.
    private native void setBlocksRemainingDown(long nativeRef, long value);


}
