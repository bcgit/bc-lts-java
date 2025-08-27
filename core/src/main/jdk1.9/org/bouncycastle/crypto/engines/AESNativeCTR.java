package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.lang.ref.Reference;

public class AESNativeCTR
        implements CTRModeCipher
{

    private CTRRefWrapper referenceWrapper = null;
    private int keyLen;


    public AESNativeCTR()
    {
    }


    public BlockCipher getUnderlyingCipher()
    {
        try
        {
            BlockCipher engine = AESEngine.newInstance();
            if (referenceWrapper != null)
            {
                byte[] k = referenceWrapper.getKey();
                if (k != null)
                {
                    engine.init(true, new KeyParameter(referenceWrapper.getKey()));
                }
            }
            return engine;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public int getBlockSize()
    {
        return 16;
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

            return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
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
        try
        {
            int extent = getBlockSize() * blockCount;

            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return processBytes(referenceWrapper.getReference(), in, inOff, extent, out, outOff);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public long skip(long numberOfBytes)
    {
        try
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return skip(referenceWrapper.getReference(), numberOfBytes);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public long seekTo(long position)
    {
        try
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return seekTo(referenceWrapper.getReference(), position);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public long getPosition()
    {
        try
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return getPosition(referenceWrapper.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        try
        {
            if (params instanceof ParametersWithIV)
            {
                ParametersWithIV ivParam = (ParametersWithIV) params;
                byte[] iv = ivParam.getIV();

                int blockSize = getBlockSize();

                int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

                if (blockSize - iv.length > maxCounterSize)
                {
                    throw new IllegalArgumentException("CTR mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
                }

                //
                // if null it's an IV changed only.
                if (ivParam.getParameters() == null)
                {
                    if (referenceWrapper == null)
                    {
                        referenceWrapper = new CTRRefWrapper(makeCTRInstance(), null);
                    }
                    init(referenceWrapper.getReference(), referenceWrapper.getKey(), iv);
                }
                else
                {
                    byte[] key = ((KeyParameter) ivParam.getParameters()).getKey();

                    switch (key.length)
                    {
                        case 16:
                        case 24:
                        case 32:
                            break;
                        default:
                            throw new IllegalArgumentException("invalid key length, key must be 16,24 or 32 bytes");
                    }


                    keyLen = key.length * 8;

                    referenceWrapper = new CTRRefWrapper(makeCTRInstance(), key);
                    init(referenceWrapper.getReference(), referenceWrapper.getKey(), iv);

                }

                reset();
            }
            else
            {
                throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
            }
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    static native long makeCTRInstance();

    @Override
    public String getAlgorithmName()
    {
        return "AES/CTR";
    }

    @Override
    public byte returnByte(byte in)
    {
        try
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return returnByte(referenceWrapper.getReference(), in);
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
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
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
            if (referenceWrapper == null)
            {
                return;
            }

            reset(referenceWrapper.getReference());
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private static native long getPosition(long reference);

    private static native int getMultiBlockSize(long ref);

    private static native long skip(long ref, long numberOfByte);

    private static native long seekTo(long ref, long position);

    static native void init(long ref, byte[] key, byte[] iv);

    private static native byte returnByte(long ref, byte b);

    private static native int processBytes(long ref, byte[] in, int inOff, int len, byte[] out, int outOff);

    private static native void reset(long ref);


    native static void dispose(long ref);


    private static class CTRRefWrapper
            extends NativeReference
    {
        private final byte[] key;

        public CTRRefWrapper(long reference, byte[] key)
        {
            super(reference, "CTR");
            this.key = key;
        }

        public byte[] getKey()
        {
            return key;
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
            AESNativeCTR.dispose(reference);
        }
    }

    public String toString()
    {
        if (keyLen > 0)
        {
            return "CTR[Native](AES[Native](" + keyLen + "))";
        }
        return "CTR[Native](AES[Native](not initialized))";
    }

}
