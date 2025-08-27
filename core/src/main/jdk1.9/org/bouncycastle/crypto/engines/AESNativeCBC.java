package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.lang.ref.Reference;

class AESNativeCBC
        implements CBCModeCipher
{
    private CBCRefWrapper referenceWrapper;

    byte[] IV = new byte[16];
    int keySize;

    private boolean encrypting;

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        try
        {
            boolean oldEncrypting = this.encrypting;

            this.encrypting = forEncryption;

            if (params instanceof ParametersWithIV)
            {
                ParametersWithIV ivParam = (ParametersWithIV) params;
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
                    // The key parameter was null which inidicates that they
                    // IV is being changed.

                    if (oldEncrypting != encrypting)
                    {
                        throw new IllegalArgumentException("cannot change encrypting state without providing key");
                    }

                    if (referenceWrapper == null)
                    {
                        throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                    }

                    // We need to use the old key because
                    // the native layer requires a both key and iv each time.
                    init(new KeyParameter(referenceWrapper.oldKey));

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

                    if (referenceWrapper == null)
                    {
                        throw new IllegalStateException("IV change attempted but not previously initialized with a key");
                    }

                    // We need to use the old key because the
                    // native layer requires a both key and iv each time.
                    init(new KeyParameter(referenceWrapper.oldKey));

                }
            }

        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private void init(KeyParameter parameters)
    {

        try
        {
            byte[] key = ((KeyParameter) parameters).getKey();


            switch (key.length)
            {
                case 16:
                case 24:
                case 32:
                    break;
                default:
                    throw new IllegalArgumentException("key must be only 16,24,or 32 bytes long.");
            }

            referenceWrapper = new CBCRefWrapper(makeNative(key.length, encrypting), Arrays.clone(key));

            if (referenceWrapper.getReference() == 0)
            {
                throw new IllegalStateException("Native CBC native instance returned a null pointer.");
            }

            init(referenceWrapper.getReference(), key, IV);
            keySize = key.length * 8;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
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

        try
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return process(referenceWrapper.getReference(), in, inOff, 1, out, outOff);
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
            // skip over spurious resets that may occur before init is called.
            if (referenceWrapper == null)
            {
                return;
            }

            reset(referenceWrapper.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public int getMultiBlockSize()
    {
        try
        {
            return getMultiBlockSize(0);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {
        try
        {

            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return process(referenceWrapper.getReference(), in, inOff, blockCount, out, outOff);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private static native int process(long ref, byte[] in, int inOff, int blockCount, byte[] out, int outOff);

    private static native int getMultiBlockSize(long ref);

    private static native int getBlockSize(long ref);

    static native long makeNative(int keyLen, boolean encryption);

    native void init(long nativeRef, byte[] key, byte[] iv);

    static native void dispose(long ref);

    private static native void reset(long nativeRef);

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        try
        {
            MultiBlockCipher eng = AESEngine.newInstance();
            eng.init(encrypting, new KeyParameter(referenceWrapper.oldKey));
            return eng;
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }


    private static class Disposer
            extends NativeDisposer
    {
        private final byte[] oldKey;

        Disposer(long ref, byte[] oldKey)
        {
            super(ref);
            this.oldKey = oldKey;
        }

        @Override
        protected void dispose(long reference)
        {
            Arrays.clear(this.oldKey);
            AESNativeCBC.dispose(reference);
        }
    }

    private class CBCRefWrapper
            extends NativeReference
    {
        private final byte[] oldKey;

        public CBCRefWrapper(long reference, byte[] oldKey)
        {
            super(reference, "CBC");
            this.oldKey = oldKey;
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference, this.oldKey);
        }
    }

    @Override
    public String toString()
    {
        return "CBC[Native](AES[Native](" + keySize + ")";
    }

}
