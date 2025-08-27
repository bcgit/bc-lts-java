package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.lang.ref.Reference;

/**
 * SHA224 implementation.
 */
class SHA224NativeDigest
        implements SavableDigest
{
    private final CryptoServicePurpose purpose;

    protected DigestRefWrapper nativeRef = null;

    SHA224NativeDigest(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        nativeRef = new DigestRefWrapper(makeNative());
        reset();
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    SHA224NativeDigest()
    {
        this(CryptoServicePurpose.ANY);
    }

    SHA224NativeDigest(SHA224NativeDigest src)
    {

        this(CryptoServicePurpose.ANY);

        byte[] state = src.getEncodedState();

        restoreFullState(nativeRef.getReference(), state, 0);
    }

    //
    // From BC-LTS, used for testing in FIPS api only.
    // ----------------------- Start Testing only methods.

    SHA224NativeDigest restoreState(byte[] state, int offset)
    {
        restoreFullState(nativeRef.getReference(), state, offset);
        return this;
    }

    //
    // ----------------------- End Testing only methods.
    //

    @Override
    public String getAlgorithmName()
    {
        return "SHA-224";
    }

    @Override
    public int getDigestSize()
    {
        return getDigestSize(nativeRef.getReference());
    }


    @Override
    public void update(byte in)
    {
        try
        {
            update(nativeRef.getReference(), in);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public void update(byte[] input, int inOff, int len)
    {
        try
        {
            update(nativeRef.getReference(), input, inOff, len);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public int doFinal(byte[] output, int outOff)
    {
        try
        {
            return doFinal(nativeRef.getReference(), output, outOff);
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
            reset(nativeRef.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public int getByteLength()
    {
        try
        {
            return getByteLength(nativeRef.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public Memoable copy()
    {
        try
        {
            return new SHA224NativeDigest(this);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public void reset(Memoable other)
    {
        try
        {
            SHA224NativeDigest dig = (SHA224NativeDigest) other;
            restoreFullState(nativeRef.getReference(), dig.getEncodedState(), 0);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    public byte[] getEncodedState()
    {
        try
        {
            int l = encodeFullState(nativeRef.getReference(), null, 0);
            byte[] state = new byte[l];
            encodeFullState(nativeRef.getReference(), state, 0);
            return state;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    void restoreFullState(byte[] encoded, int offset)
    {
        try
        {
            restoreFullState(nativeRef.getReference(), encoded, offset);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    public String toString()
    {
        return "SHA224[Native]()";
    }

    static native long makeNative();

    static native void destroy(long nativeRef);

    static native int getDigestSize(long nativeRef);

    static native void update(long nativeRef, byte in);

    static native void update(long nativeRef, byte[] in, int inOff, int len);

    static native int doFinal(long nativeRef, byte[] out, int outOff);

    static native void reset(long nativeRef);

    static native int getByteLength(long nativeRef);

    static native int encodeFullState(long nativeRef, byte[] buffer, int offset);

    static native void restoreFullState(long reference, byte[] encoded, int offset);

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, 224, purpose);
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
            destroy(reference);
        }
    }

    private static class DigestRefWrapper
            extends NativeReference
    {

        public DigestRefWrapper(long reference)
        {
            super(reference, "SHA224");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}






