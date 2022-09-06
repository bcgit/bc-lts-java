package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.dispose.Disposable;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.dispose.DisposalDaemon;


public class AESNativeEngine
    implements MultiBlockCipher
{
    private RefWrapper wrapper = null;

    public AESNativeEngine()
    {

    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            byte[] key = ((KeyParameter)params).getKey();

            switch (key.length)
            {
            case 16:
            case 24:
            case 32:
                synchronized (this)
                {
                    if (wrapper != null)
                    {
                        wrapper.dispose();
                    }
                    wrapper = new RefWrapper(makeInstance(key.length, forEncryption));
                    DisposalDaemon.addDisposable(wrapper);
                }
                break;

            default:
                throw new IllegalArgumentException("key must be 16, 24 or 32 bytes");
            }

            init(wrapper.nativeRef, key);

            return;
        }


        throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
    }

    @Override
    public String getAlgorithmName()
    {
        return "AES";
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
        if (wrapper == null)
        {
            throw new IllegalStateException("AES engine not initialised");
        }

        if (inOff > (in.length - getBlockSize()))
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outOff > (out.length - getBlockSize()))
        {
            throw new OutputLengthException("output buffer too short");
        }
        return process(wrapper.nativeRef, in, inOff, 1, out, outOff);
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
        return process(wrapper.nativeRef, in, inOff, blockCount, out, outOff);
    }

    @Override
    public void reset()
    {
        if (wrapper != null)
        {
            reset(wrapper.nativeRef);
        }
    }


    private static native void reset(long ref);

    private static native int process(long ref, byte[] in, int inOff, int blocks, byte[] out, int outOff);

    private static native int getMultiBlockSize(long nativeRef);

    private static native int getBlockSize(long ref);

    private static native long makeInstance(int length, boolean forEncryption);

    private static native void dispose(long ref);

    private static native void init(long nativeRef, byte[] key);


    private static class RefWrapper
        implements Disposable
    {
        private final long nativeRef;
        private boolean disposed = false;

        private RefWrapper(long nativeRef)
        {
            this.nativeRef = nativeRef;
        }


        @Override
        public void dispose()
        {
            if (!disposed)
            {
                AESNativeEngine.dispose(nativeRef);
                disposed = true;
            }
        }

    }

}
