package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.NativeService;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class AESNativeCFB
    implements CFBModeCipher, NativeService
{

    private final int bitSize;
    private CFBRefWrapper referenceWrapper;

    private byte[] oldKey;
    private byte[] oldIv;
    private boolean encrypting;

    public AESNativeCFB()
    {
        this(128);
    }

    public AESNativeCFB(int bitSize)
    {
        this.bitSize = bitSize;
        switch (bitSize)
        {
        case 128:
            break;
        default:
            throw new IllegalArgumentException("native feedback bit size can only be 128");
        }
    }

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

            if (iv.length > getBlockSize() || iv.length < 1)
            {
                throw new IllegalArgumentException("initialisation vector must be between one and block size length");
            }

            if (iv.length < getBlockSize())
            {
                byte[] newIv = new byte[getBlockSize()];
                System.arraycopy(iv, 0, iv, newIv.length - iv.length, iv.length);
                iv = newIv;
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


        referenceWrapper = new CFBRefWrapper(makeNative(key.length));
        init(referenceWrapper.getReference(), encrypting, key, iv);

    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CBC";
    }

    @Override
    public byte returnByte(byte in)
    {
        return processByte(referenceWrapper.getReference(), in);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (inOff < 0)
        {
            throw new DataLengthException("inOff is negative");
        }

        if (len < 0)
        {
            throw new DataLengthException("len is negative");
        }

        if (outOff < 0)
        {
            throw new DataLengthException("outOff is negative");
        }

        if (inOff + len > in.length)
        {
            throw new DataLengthException("input buffer too small");
        }
        if (outOff + len > out.length)
        {
            throw new OutputLengthException("output buffer too small");
        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        //
        // Total bytes we can process.
        //
        len = Math.min(len, out.length - outOff);

        return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
    }

    @Override
    public int getBlockSize()
    {
        return bitSize / 8;
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

        return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);
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
        return bitSize / 8;
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        if (inOff < 0)
        {
            throw new DataLengthException("inOff is negative");
        }

        if (blockCount < 0)
        {
            throw new DataLengthException("block count is negative");
        }

        if (outOff < 0)
        {
            throw new DataLengthException("outOff is negative");
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
            throw new IllegalStateException("CFB engine not initialised");
        }

        return processBytes(in, inOff, blockCount * getBlockSize(), out, outOff);
    }


    private static native byte processByte(long ref, byte in);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException;

    private static native long makeNative(int keyLen);

    private native void init(long nativeRef, boolean encrypting, byte[] key, byte[] iv);

    private static native void dispose(long ref);

    private static native void reset(long nativeRef);


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
            AESNativeCFB.dispose(reference);
        }
    }

    private static class CFBRefWrapper
        extends NativeReference
    {

        public CFBRefWrapper(long reference)
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