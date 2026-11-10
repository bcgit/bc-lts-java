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

import java.lang.ref.Reference;

class AESNativeGCM
        implements GCMModeCipher
{
    private GCMRefWrapper refWrapper;
    private byte[] oldNonce;
    private boolean forEncryption = false;
    private boolean initialised = false;
    // set once encryption under the current nonce has used keystream or produced a tag; a reset
    // after that cannot let the cipher encrypt again.
    private boolean nonceUsed = false;
    private byte[] keptMac = null;
    // the tag length in bytes, from the last successful init.
    private int macSizeBytes = 16;


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


    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        try
        {
            this.forEncryption = forEncryption;
            // a failed init leaves the cipher uninitialised, never armed with the previous state.
            initialised = false;
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
                CipherParameters innerParameters = param.getParameters();
                if (innerParameters != null && !(innerParameters instanceof KeyParameter))
                {
                    throw new IllegalArgumentException("invalid parameters passed to GCM");
                }
                keyParam = (KeyParameter) innerParameters;
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
            else if (refWrapper != null && refWrapper.key != null)
            {
                // if keyParam is null we're reusing the last key.
                key = refWrapper.key;
            }
            else
            {
                throw new IllegalArgumentException("Key must be specified in initial init");
            }

            // the remembered key and nonce change only once the new ones are in use: a failed init
            // must not displace them, or the old pair would then pass the reuse check.
            GCMRefWrapper ref = new GCMRefWrapper(makeInstance(key.length, forEncryption), Arrays.clone(key));

            initNative(
                    ref.getReference(),
                    forEncryption, ref.key,
                    newNonce, initialAssociatedText, macSize);

            refWrapper = ref;
            oldNonce = newNonce;


            nonceUsed = false;
            macSizeBytes = macSize / 8;
            initialised = true;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }



    @Override
    public String getAlgorithmName()
    {
        return "AES/GCM";
    }

    @Override
    public void processAADByte(byte in)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException("GCM is uninitialized");
            }

            checkStatus();

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
                throw new IllegalStateException("GCM is uninitialized");
            }

            checkStatus();

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
                throw new IllegalStateException("GCM is uninitialized");
            }

            checkStatus();
            if (forEncryption)
            {
                nonceUsed = true;
            }

            return processByte(refWrapper.getReference(), in, out, outOff);
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
                throw new IllegalStateException("GCM is uninitialized");
            }

            checkStatus();
            if (forEncryption && len > 0)
            {
                nonceUsed = true;
            }

            return processBytes(refWrapper.getReference(), in, inOff, len, out, outOff);
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
            checkStatus();


            if (forEncryption)
            {
                nonceUsed = true;
            }

            int len;
            try
            {
                len = doFinal(refWrapper.getReference(), out, outOff);
            }
            catch (InvalidCipherTextException e)
            {
                // getMac() must not return the expected tag: it is a valid tag for the rejected input. As for
                // GCMBlockCipher, it reads as zeros until the cipher is reset or re-initialised.
                keptMac = new byte[macSizeBytes];
                throw e;
            }

            //
            // BlockCipherTest, testing ShortTagException.
            //

            resetKeepMac();
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
            if (keptMac != null)
            {
                return Arrays.clone(keptMac);
            }
            if (refWrapper == null)
            {
                // as for GCMBlockCipher, no MAC before init.
                return new byte[0];
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
                // as for GCMBlockCipher before init: decryption, zero length MAC.
                return len < 0 ? 0 : len - len % 16;
            }
            return getUpdateOutputSize(refWrapper.getReference(), len);
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
                // as for GCMBlockCipher before init: decryption, zero length MAC.
                return len < 0 ? 0 : len;
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
            if (refWrapper == null)
            {
                // deal with reset being called before init.
                return;
            }

            // as for GCMBlockCipher, a reset discards the MAC of the last message.
            keptMac = null;
            reset(refWrapper.getReference());
            if (forEncryption && nonceUsed)
            {
                initialised = false;
            }
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private void resetKeepMac()
    {
        try
        {
            if (refWrapper == null)
            {
                // deal with reset being called before init.
                return;
            }

            // the MAC of this message, not one kept from an earlier one.
            keptMac = getMac(refWrapper.getReference());
            reset(refWrapper.getReference());
            if (forEncryption && nonceUsed)
            {
                initialised = false;
            }
        }
        finally
        {
            Reference.reachabilityFence(this);
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

    // the JNI layer throws InvalidCipherTextException when the tag check fails
    private static native int doFinal(long ref, byte[] out, int outOff)
        throws InvalidCipherTextException;

    private static native int getUpdateOutputSize(long ref, int len);

    private static native int getOutputSize(long ref, int len);

    private static native byte[] getMac(long ref);

    /**
     * Set blocks remaining but only to a lesser value and only if the transformation has processed no data.
     * Functionality limited to within the module only.
     *
     * @param value the step value.
     */
    void setBlocksRemainingDown(long value)
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException("GCM is uninitialized");
            }
            setBlocksRemainingDown(refWrapper.getReference(), value);
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    // Set the blocks remaining, but only to a lesser value.
    // This is intended for testing only and will throw from the native side if the
    // transformation has processed any data.
    private native void setBlocksRemainingDown(long nativeRef, long value);


    private static class GCMRefWrapper
            extends NativeReference
    {
        private final byte[] key;

        public GCMRefWrapper(long reference, byte[] key)
        {
            super(reference, "GCM", new Disposer(reference, key));
            this.key = key;
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

    @Override
    public String toString()
    {
        try
        {
            if (refWrapper != null && refWrapper.key != null)
            {
                return "GCM[Native](AES[Native](" + (refWrapper.key.length * 8) + "))";
            }
            return "GCM[Native](AES[Native](not initialized))";
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }
}
