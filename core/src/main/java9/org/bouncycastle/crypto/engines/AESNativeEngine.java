package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.lang.ref.Reference;

class AESNativeEngine
        extends DefaultMultiBlockCipher
        implements NativeBlockCipherProvider, NativeCCMProvider, NativeEAXProvider, NativeOCBProvider, NativeGCMSIVProvider
{
    protected NativeReference wrapper = null;
    private int keyLen = 0;

    AESNativeEngine()
    {
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 256));
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
    {
        try
        {
            if (params instanceof KeyParameter)
            {
                byte[] key = ((KeyParameter) params).getKey();

                switch (key.length)
                {
                    case 16:
                    case 24:
                    case 32:
                        wrapper = new ECBNativeRef(makeInstance(key.length, forEncryption));
                        break;

                    default:
                        throw new IllegalArgumentException("key must be 16, 24 or 32 bytes");
                }

                CryptoServicesRegistrar.checkConstraints(
                        new DefaultServiceProperties(
                                getAlgorithmName(),
                                key.length * 8,
                                params,
                                forEncryption ? CryptoServicePurpose.ENCRYPTION : CryptoServicePurpose.DECRYPTION
                        ));


                init(wrapper.getReference(), key);

                keyLen = key.length * 8;

                return;

            }


            throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
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
        try
        {
            if (wrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }

            return process(wrapper.getReference(), in, inOff, 1, out, outOff);
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
            if (wrapper == null)
            {
                throw new IllegalStateException("not initialized");
            }


            return process(wrapper.getReference(), in, inOff, blockCount, out, outOff);
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
            if (wrapper == null)
            {
                return;
            }
            reset(wrapper.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public GCMModeCipher createGCM()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
        {
            return new AESNativeGCM();
        }

        return new GCMBlockCipher(new AESEngine());
    }

    @Override
    public GCMSIVModeCipher createGCMSIV()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCMSIV))
        {
            return new AESNativeGCMSIV();
        }
        return new GCMSIVBlockCipher(new AESNativeEngine());
    }

    @Override
    public CBCModeCipher createCBC()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CBC))
        {
            return new AESNativeCBC();
        }
        return new CBCBlockCipher(new AESNativeEngine());
    }

    @Override
    public CFBModeCipher createCFB(int bitSize)
    {
        if (bitSize % 8 != 0 || bitSize == 0 || bitSize > 128)
        {
            throw new IllegalArgumentException("invalid CFB bitsize: " + bitSize);
        }

        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CFB))
        {
            return new AESNativeCFB(bitSize);
        }

        return new CFBBlockCipher(new AESNativeEngine(), bitSize);
    }


    @Override
    public CTRModeCipher createCTR()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CTR))
        {
            return new AESNativeCTR();
        }

        return new SICBlockCipher(AESEngine.newInstance());
    }

    @Override
    public CCMModeCipher createCCM()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CCM))
        {
            return new AESNativeCCM();
        }

        return new CCMBlockCipher(AESEngine.newInstance());
    }

    @Override
    public EAXModeCipher createEAX()
    {
        return new EAXBlockCipher(AESEngine.newInstance());
    }

    @Override
    public OCBModeCipher createOCB()
    {
        return new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance());
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
            AESNativeEngine.dispose(reference);
        }
    }

    private static class ECBNativeRef
            extends NativeReference
    {

        public ECBNativeRef(long reference)
        {
            super(reference, "ECB");
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }

    public String toString()
    {
        return "AES[Native](" + keyLen + ")";
    }

    private static native void reset(long ref);

    private static native int process(long ref, byte[] in, int inOff, int blocks, byte[] out, int outOff);

    private static native int getMultiBlockSize(long nativeRef);

    private static native int getBlockSize(long ref);

    static native long makeInstance(int length, boolean forEncryption);

    static native void dispose(long ref);

    static native void init(long nativeRef, byte[] key);
}
