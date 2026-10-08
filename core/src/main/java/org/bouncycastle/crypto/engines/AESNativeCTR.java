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
        synchronized (this)
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
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return processBytes(referenceWrapper.getReference(), in, inOff, getBlockSize(), out, outOff);
        }
    }

    @Override
    public int getMultiBlockSize()
    {
        synchronized (this)
        {
            return getMultiBlockSize(0);
        }
    }

    @Override
    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
    {

        synchronized (this)
        {
            int extent = getBlockSize() * blockCount;

            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return processBytes(referenceWrapper.getReference(), in, inOff, extent, out, outOff);
        }
    }

    @Override
    public long skip(long numberOfBytes)
    {
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return skip(referenceWrapper.getReference(), numberOfBytes);
        }
    }

    @Override
    public long seekTo(long position)
    {
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return seekTo(referenceWrapper.getReference(), position);
        }
    }

    @Override
    public long getPosition()
    {
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return getPosition(referenceWrapper.getReference());
        }
    }


    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        synchronized (this)
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
                        // there is no key to reuse, which the native init refuses, so the engine stays
                        // uninitialised rather than holding a context with no key schedule.
                        CTRRefWrapper ref = new CTRRefWrapper(makeCTRInstance(), null);
                        init(ref.getReference(), null, iv);
                        referenceWrapper = ref;
                    }
                    else
                    {
                        init(referenceWrapper.getReference(), referenceWrapper.getKey(), iv);
                    }
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

                    // a failed init leaves the engine uninitialised, never holding a context that has no
                    // key schedule in it.
                    referenceWrapper = null;
                    CTRRefWrapper ref = new CTRRefWrapper(makeCTRInstance(), Arrays.clone(key));
                    init(ref.getReference(), ref.getKey(), iv);
                    referenceWrapper = ref;

                }

                reset();
            }
            else
            {
                throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
            }
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
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }
            return returnByte(referenceWrapper.getReference(), in);
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

            return processBytes(referenceWrapper.getReference(), in, inOff, len, out, outOff);
        }
    }


    @Override
    public void reset()
    {
        synchronized (this)
        {
            if (referenceWrapper == null)
            {
                return;
            }

            reset(referenceWrapper.getReference());
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
            super(reference, "CTR", new Disposer(reference, key));
            this.key = key;
        }

        public byte[] getKey()
        {
            return key;
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
