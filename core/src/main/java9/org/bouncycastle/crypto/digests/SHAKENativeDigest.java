package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

import java.lang.ref.Reference;

/**
 * SHAKE implementation.
 */
public class SHAKENativeDigest
        implements SavableDigestXof
{
    private final CryptoServicePurpose purpose;

    protected DigestRefWrapper nativeRef = null;
    private int bitLen;


    public SHAKENativeDigest(CryptoServicePurpose purpose)
    {
        this(128, purpose);
    }

    public SHAKENativeDigest(int bitLen, CryptoServicePurpose purpose)
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.SHA3))
        {
            throw new IllegalStateException("no native SHAKE support");
        }

        this.purpose = purpose;
        this.bitLen = bitLen;
        nativeRef = new DigestRefWrapper(makeNative(bitLen));
        reset();
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public SHAKENativeDigest(int bitLen)
    {
        this(bitLen, CryptoServicePurpose.ANY);
    }

    public SHAKENativeDigest()
    {
        this(CryptoServicePurpose.ANY);
    }

    public SHAKENativeDigest(SHAKENativeDigest src)
    {
        this(CryptoServicePurpose.ANY);
        byte[] state = src.getEncodedState();
        restoreFullState(nativeRef.getReference(), state, 0);
    }

    public SHAKENativeDigest(byte[] encoded, CryptoServicePurpose purpose)
    {
        this(purpose);
        restoreFullState(nativeRef.getReference(), encoded, 0);
    }

    public SHAKENativeDigest(byte[] encoded)
    {
        this();
        restoreFullState(nativeRef.getReference(), encoded, 0);
    }


    SHAKENativeDigest restoreState(byte[] state, int offset)
    {
        try
        {
            restoreFullState(nativeRef.getReference(), state, offset);
            return this;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    //
    // ----------------------- End Testing only methods.
    //

    @Override
    public String getAlgorithmName()
    {

        return "SHAKE" + bitLen;
    }

    @Override
    public int getDigestSize()
    {
        try
        {
            return getDigestSize(nativeRef.getReference());
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
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
            int i = doFinal(nativeRef.getReference(), output, outOff);
            return i;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int doFinal(byte[] out, int outOff, int outLen)
    {
        try
        {
            int i = doFinal(nativeRef.getReference(), out, outOff, outLen);
            return i;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public int doOutput(byte[] out, int outOff, int outLen)
    {
        try
        {
            return doOutput(nativeRef.getReference(), out, outOff, outLen);
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
            return new SHAKENativeDigest(this);
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
            SHAKENativeDigest dig = (SHAKENativeDigest) other;
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
        return "SHAKE[Native]()";
    }

    static native long makeNative(int bitLen);

    static native void destroy(long nativeRef);

    static native int getDigestSize(long nativeRef);

    static native void update(long nativeRef, byte in);

    static native void update(long nativeRef, byte[] in, int inOff, int len);

    static native int doFinal(long nativeRef, byte[] out, int outOff, int len);

    static native int doFinal(long nativeRef, byte[] out, int outOff);

    static native int doOutput(long nativeRef, byte[] out, int outOff, int len);

    static native void reset(long nativeRef);

    static native int getByteLength(long nativeRef);

    static native int encodeFullState(long nativeRef, byte[] buffer, int offset);

    static native void restoreFullState(long reference, byte[] encoded, int offset);

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, bitLen, purpose);
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

    protected static class DigestRefWrapper
            extends NativeReference
    {

        public DigestRefWrapper(long reference)
        {
            super(reference, "SHAKE");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}






