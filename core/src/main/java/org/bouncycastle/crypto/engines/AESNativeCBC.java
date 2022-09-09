package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DefaultMultiBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeReference;


public class AESNativeCBC
    extends DefaultMultiBlockCipher
{

    private CBCRefWrapper wrapper;

    private byte[] oldKey;
    private byte[] oldIv;
    private boolean encrypting;

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {

        if (wrapper != null)
        {
            wrapper.dispose();
        }

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

        }

        if (key == null && oldEncrypting != encrypting)
        {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }

        if (iv == null)
        {
            throw new IllegalArgumentException("iv is null");
        }

        wrapper = new CBCRefWrapper(makeNative(key.length, encrypting));
        init(wrapper.getReference(), key, iv);

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

        if ((inOff + getBlockSize()) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outOff + getBlockSize() > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }


        return process(wrapper.getReference(), in, inOff, 1, out, outOff);
    }

    @Override
    public void reset()
    {
        // skip over spurious resets that may occur before init is called.
        if (wrapper == null || wrapper.isDisposed())
        {
            return;
        }

        reset(wrapper.getReference());

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
        if ((inOff + getBlockSize()) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outOff + getBlockSize() > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (blockCount < 0)
        {
            throw new DataLengthException("block count < 0");
        }

        if (wrapper == null || wrapper.isDisposed())
        {
            throw new IllegalStateException("CBC engine not initialised");
        }

        return process(wrapper.getReference(), in, inOff, blockCount, out, outOff);
    }

    private static native int process(long ref, byte[] in, int inOff, int blockCount, byte[] out, int outOff);

    private static native int getMultiBlockSize(int i);

    private static native int getBlockSize(long ref);

    private static native long makeNative(int keyLen, boolean encryption);

    private native void init(long nativeRef, byte[] key, byte[] iv);

    private static native void dispose(long ref);

    private static native void reset(long nativeRef);

    private static class CBCRefWrapper extends NativeReference
    {


        public CBCRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        protected void destroy(long reference)
        {
            AESNativeCBC.dispose(reference);
        }
    }


}
