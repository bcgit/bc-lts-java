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

    private byte[] oldKey;
    private byte[] oldIv;
    private boolean encrypting;

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {

        boolean oldEncrypting = this.encrypting;

        this.encrypting = forEncryption;

        byte[] key = null;
        byte[] iv = null;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            iv = ivParam.getIV();
            if (iv.length != getBlockSize())
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }

            oldIv = Arrays.clone(iv);

            if (ivParam.getParameters() != null)
            {
                key = ((KeyParameter)ivParam.getParameters()).getKey();
            }

            if (key != null)
            {
                oldEncrypting = encrypting; // Can change because key is supplied.
                oldKey = Arrays.clone(key);
            }
            else
            {
                // Use old key, it may be null but that is tested later.
                key = oldKey;
            }
        }
        else
        {
            //
            // Change of key.
            //

            if (params instanceof KeyParameter)
            {
                key = ((KeyParameter)params).getKey();
                oldKey = Arrays.clone(key);
                iv = oldIv;
            }
            else
            {
                key = oldKey;
                iv = oldIv;
            }

        }

        if (key == null && oldEncrypting != encrypting)
        {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }

        if (iv == null)
        {
            iv = new byte[getBlockSize()];
        }

        CryptoServicesRegistrar.checkConstraints(
            new DefaultServiceProperties(
                getAlgorithmName(),
                key.length * 8,
                params,
                forEncryption ? CryptoServicePurpose.ENCRYPTION : CryptoServicePurpose.DECRYPTION
            ));


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

        init(referenceWrapper.getReference(), key, iv);

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
            throw new IllegalStateException("not initialzed");
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
            throw new DataLengthException("input offset is negative");
        }

        if (outOff < 0)
        {
            throw new DataLengthException("output offset is negative");
        }

        if (blockCount < 0)
        {
            throw new DataLengthException("blockCount offset is negative");
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
            throw new IllegalStateException("CBC engine not initialised");
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
            AESNativeCBC.dispose(reference);
        }
    }

    private static class CBCRefWrapper
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
