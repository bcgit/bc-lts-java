package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.NativeService;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class AESNativeCBC
    implements CBCModeCipher, NativeService
{

    private CBCRefWrapper referenceWrapper;

    byte[] IV = new byte[16];
    byte[] oldKey;

    private boolean encrypting;

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        boolean oldEncrypting = this.encrypting;

        this.encrypting = forEncryption;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();

            if (iv.length != getBlockSize())
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }

            System.arraycopy(iv, 0, IV, 0, iv.length);

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                init((KeyParameter) ivParam.getParameters());
                // cipher.init(encrypting, ivParam.getParameters());
            }
            else
            {
                // The key parameter was null which indicates that the
                // IV is being changed.

                if (oldEncrypting != encrypting)
                {
                    throw new IllegalArgumentException("cannot change encrypting state without providing key.");
                }

                if (oldKey == null)
                {
                    throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                }

                // We need to use the old key because
                // the native layer requires a both key and iv each time.
                init(new KeyParameter(oldKey));

            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                init((KeyParameter) params);
                // cipher.init(encrypting, params);
            }
            else
            {
                if (oldEncrypting != encrypting)
                {
                    throw new IllegalArgumentException("cannot change encrypting state without providing key.");
                }

                if (oldKey == null)
                {
                    throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                }

                // We need to use the old key because the
                // native layer requires a both key and iv each time.
                init(new KeyParameter(oldKey));

            }
        }

    }

    private void init(KeyParameter parameters)
    {

        byte[] key = null;

        if (parameters instanceof KeyParameter)
        {
            key = ((KeyParameter)parameters).getKey();
        }

        switch (key.length)
        {
        case 16:
        case 24:
        case 32:
            break;
        default:
            throw new IllegalStateException("key must be only 16,24,or 32 bytes long.");
        }

        referenceWrapper = new CBCRefWrapper(makeNative(key.length, encrypting));

        if (referenceWrapper.getReference() == 0)
        {
            throw new IllegalStateException("Native CBC native instance returned a null pointer.");
        }

        oldKey = Arrays.clone(key);

        init(referenceWrapper.getReference(), key, IV);

    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CBC";
    }

    @Override
    public int getBlockSize()
    {
        return getBlockSize(0);
    }


    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        if (inOff < 0)
        {
            throw new DataLengthException("inOff is negative");
        }

        if (outOff < 0)
        {
            throw new DataLengthException("outOff is negative");
        }

        if ((inOff + getBlockSize()) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outOff + getBlockSize() > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(referenceWrapper.getReference(), in, inOff, 1, out, outOff);
    }

    @Override
    public void reset()
    {
        // skip over spurious resets that may occur before init is called.
        if (referenceWrapper == null)
        {
            return;
        }

        reset(referenceWrapper.getReference());

    }


    @Override
    public int getMultiBlockSize()
    {
        return getMultiBlockSize(0);
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (inOff < 0)
        {
            throw new DataLengthException("inOff is negative");
        }

        if (outOff < 0)
        {
            throw new DataLengthException("outOff is negative");
        }

        if (blockCount < 0)
        {
            throw new DataLengthException("blockCount is negative");
        }

        int extent = getBlockSize() * blockCount;

        if (inOff + extent > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outOff + extent > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return process(referenceWrapper.getReference(), in, inOff, blockCount, out, outOff);
    }

    private static native int process(long ref, byte[] in, int inOff, int blockCount, byte[] out, int outOff);

    private static native int getMultiBlockSize(int i);

    private static native int getBlockSize(long ref);

    private static native long makeNative(int keyLen, boolean encryption);

    private native void init(long nativeRef, byte[] key, byte[] iv);

    private static native void dispose(long ref);

    private static native void reset(long nativeRef);

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        BlockCipher engine = AESEngine.newInstance();
        engine.init(encrypting, new KeyParameter(oldKey));
        return engine;
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
            Arrays.clear(oldKey);
            Arrays.clear(IV);
            AESNativeCBC.dispose(reference);
        }
    }

    private class CBCRefWrapper
        extends NativeReference
    {

        public CBCRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }


}
