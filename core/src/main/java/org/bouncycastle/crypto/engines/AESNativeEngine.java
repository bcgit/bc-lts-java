package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.dispose.Disposable;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.dispose.DisposalDaemon;


public class AESNativeEngine
    implements BlockCipher, Disposable
{
    private long nativeRef = 0;

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
                    if (nativeRef != 0)
                    {
                        dispose(nativeRef);
                    }
                    nativeRef = makeInstance(key.length, forEncryption);
                    DisposalDaemon.addDisposable(this);
                }
                break;
            }

            init(nativeRef, key);

            return;
        }


        throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
    }

    @Override
    public String getAlgorithmName()
    {
        return null;
    }

    @Override
    public int getBlockSize()
    {
        return getBlockSize(nativeRef);
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        return process(nativeRef, in, inOff, out, outOff);
    }


    @Override
    public void reset()
    {
        reset(nativeRef);
    }

    private native void reset(long ref);

    private native int process(long ref, byte[] in, int inOff, byte[] out, int outOff);

    private native int getBlockSize(long ref);

    private native long makeInstance(int length, boolean forEncryption);

    private native void dispose(long ref);

    private native void init(long nativeRef, byte[] key);

    @Override
    public synchronized void dispose()
    {
        if (nativeRef != 0)
        {
            dispose(nativeRef);
            nativeRef = 0;
        }
    }
}
