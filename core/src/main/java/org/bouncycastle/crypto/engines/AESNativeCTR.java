package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

public class AESNativeCTR
    implements CTRModeCipher, MultiBlockCipher
{

    private CTRRefWrapper referenceWrapper = null;
    private int keyLen;
    private byte[] lastKey;

    public AESNativeCTR()
    {
    }


    public BlockCipher getUnderlyingCipher()
    {
        BlockCipher engine = AESEngine.newInstance();
        if (lastKey != null)
        {
            engine.init(true, new KeyParameter(lastKey));
        }
        return engine;
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
//        if (inOff < 0)
//        {
//            throw new DataLengthException("inOff is negative");
//        }
//
//        if (outOff < 0)
//        {
//            throw new DataLengthException("outOff is negative");
//        }
//
//        if ((inOff + getBlockSize()) > in.length)
//        {
//            throw new DataLengthException("input buffer too short");
//        }
//
//        if (outOff + getBlockSize() > out.length)
//        {
//            throw new DataLengthException("output buffer too short");
//        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);

    }

    @Override
    public int getMultiBlockSize()
    {
        return getMultiBlockSize(referenceWrapper.getReference());
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

//        if (inOff < 0)
//        {
//            throw new DataLengthException("inOff is negative");
//        }
//
//        if (outOff < 0)
//        {
//            throw new DataLengthException("outOff is negative");
//        }
//
//        if (blockCount < 0)
//        {
//            throw new DataLengthException("blockCount is negative");
//        }
//
        int extent = getBlockSize() * blockCount;
//
//        if (inOff + extent > in.length)
//        {
//            throw new DataLengthException("input buffer too short");
//        }
//
//        if (outOff + extent > out.length)
//        {
//            throw new DataLengthException("output buffer too short");
//        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, extent, out, outOff);

    }

    @Override
    public long skip(long numberOfBytes)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return skip(referenceWrapper.getReference(), numberOfBytes);
    }

    @Override
    public long seekTo(long position)
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return seekTo(referenceWrapper.getReference(), position);
    }

    @Override
    public long getPosition()
    {
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return getPosition(referenceWrapper.getReference());
    }


    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();

            int blockSize = getBlockSize();

            int maxCounterSize = (8 > blockSize / 2) ? blockSize / 2 : 8;

            if (blockSize - iv.length > maxCounterSize)
            {
                throw new IllegalArgumentException("CTR mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
            }

            if (referenceWrapper == null)
            {
                referenceWrapper = new CTRRefWrapper(makeCTRInstance());
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() == null)
            {
                init(referenceWrapper.getReference(), null, iv);
            }
            else
            {
                byte[] key = ((KeyParameter)ivParam.getParameters()).getKey();

                switch (key.length)
                {
                case 16:
                case 24:
                case 32:
                    break;
                default:
                    throw new IllegalArgumentException("invalid key length, key must be 16,24 or 32 bytes");
                }

                init(referenceWrapper.getReference(), key, iv);
                lastKey = Arrays.clone(key);
                keyLen = key.length * 8;
            }

            reset();
        }
        else
        {
            throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
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
        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }
        return returnByte(referenceWrapper.getReference(), in);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
//        if (inOff < 0)
//        {
//            throw new DataLengthException("inOff is negative");
//        }
//
//        if (outOff < 0)
//        {
//            throw new DataLengthException("outOff is negative");
//        }
//
//        if (len < 0)
//        {
//            throw new DataLengthException("len is negative");
//        }
//
//        if (inOff + len > in.length)
//        {
//            throw new DataLengthException("input buffer too short");
//        }
//
//        if (outOff + len > out.length)
//        {
//            throw new DataLengthException("output buffer too short");
//        }

        if (referenceWrapper == null)
        {
            throw new IllegalStateException("not initialized");
        }

        return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
    }


    @Override
    public void reset()
    {
        if (referenceWrapper == null)
        {
            return;
        }

        reset(referenceWrapper.getReference());
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
        public CTRRefWrapper(long reference)
        {
            super(reference,"CTR");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }

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
