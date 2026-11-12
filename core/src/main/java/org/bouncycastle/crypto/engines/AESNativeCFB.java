package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class AESNativeCFB
        implements CFBModeCipher
{
    private final int bitSize;
    private CFBRefWrapper referenceWrapper;

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
        synchronized (this)
        {
            this.encrypting = forEncryption;

            //
            // This follows CFBBlockCipher: an IV-only or null init reuses the key, a key-only or
            // null init reuses the IV, an IV not yet set is zero, and the direction may change
            // without a new key.
            //
            byte[] key = null;

            if (params instanceof ParametersWithIV)
            {
                ParametersWithIV ivParam = (ParametersWithIV) params;
                byte[] iv = ivParam.getIV();

                if (iv.length > getBlockSize() || iv.length < 1)
                {
                    throw new IllegalArgumentException("initialisation vector must be between one and block size length");
                }

                if (iv.length < getBlockSize())
                {
                    byte[] newIv = new byte[getBlockSize()];
                    System.arraycopy(iv, 0, newIv, newIv.length - iv.length, iv.length);
                    iv = newIv;
                }

                oldIv = Arrays.clone(iv);

                params = ivParam.getParameters();
            }

            if (params instanceof KeyParameter)
            {
                key = Arrays.clone(((KeyParameter) params).getKey());
                if (key == null)
                {
                    throw new IllegalArgumentException("key was null");
                }
            }
            else if (params != null)
            {
                throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
            }
            else if (referenceWrapper != null)
            {
                key = Arrays.clone(referenceWrapper.getKey());
            }
            else
            {
                // no key yet: as with CFBBlockCipher the engine stays uninitialised until one is
                // supplied, and refuses to process data until then.
                return;
            }

            if (oldIv == null)
            {
                oldIv = new byte[getBlockSize()];
            }

            // a failed init leaves the engine uninitialised, never holding a context that has no
            // key schedule in it.
            referenceWrapper = null;
            CFBRefWrapper ref = new CFBRefWrapper(makeNative(encrypting, key.length), key);
            init(ref.getReference(), ref.getKey(), oldIv);
            referenceWrapper = ref;
        }
    }


    @Override
    public String getAlgorithmName()
    {
        return "AES/CFB";
    }

    @Override
    public byte returnByte(byte in)
    {
        synchronized (this)
        {
            return processByte(referenceWrapper.getReference(), in);
        }
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException
    {

        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }


            inOff = NativeOverlap.inputOffset(in, inOff, len, out, outOff);

            return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
        }
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
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            inOff = NativeOverlap.inputOffset(in, inOff, getBlockSize(), out, outOff);

            return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);
        }
    }

    @Override
    public void reset()
    {
        synchronized (this)
        {
            // skip over spurious resets that may occur before init is called.
            if (referenceWrapper == null)
            {
                return;
            }

            reset(referenceWrapper.getReference());
        }
    }


    @Override
    public int getMultiBlockSize()
    {
        return getNativeMultiBlockSize();
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {

        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("CFB engine not initialized");
            }

            return processBytes(in, inOff, blockCount * getBlockSize(), out, outOff);
        }
    }


    private static native byte processByte(long ref, byte in);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException;

    static native long makeNative(boolean encrypting, int keyLen);

    native void init(long nativeRef, byte[] key, byte[] iv);

    static native void dispose(long ref);

    static native int getNativeMultiBlockSize();

    private static native void reset(long nativeRef);


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
            AESNativeCFB.dispose(reference);
        }
    }

    private static class CFBRefWrapper
            extends NativeReference
    {

        private final byte[] key;

        public CFBRefWrapper(long reference, byte[] key)
        {
            super(reference, "CFB", new Disposer(reference, key));
            this.key = key;
        }

        public byte[] getKey()
        {
            return key;
        }
    }

    public String toString()
    {
        synchronized (this)
        {
            if (referenceWrapper != null && referenceWrapper.getKey() != null)
            {
                return "CFB[Native](AES[Native](" + (referenceWrapper.getKey().length * 8) + "))";
            }
            return "CFB[Native](AES[Native](not initialized))";
        }
    }

}
