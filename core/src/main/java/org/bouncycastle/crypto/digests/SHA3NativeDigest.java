package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

/**
 * SHA3 implementation.
 */
public class SHA3NativeDigest
        implements SavableDigest
{
    private final CryptoServicePurpose purpose;

    protected DigestRefWrapper nativeRef = null;
    private int bitLen;


    public SHA3NativeDigest(CryptoServicePurpose purpose)
    {
        this(256, purpose);
    }

    public SHA3NativeDigest(int bitLen, CryptoServicePurpose purpose)
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.SHA3))
        {
            throw new IllegalStateException("no native SHA3 support");
        }

        this.purpose = purpose;
        this.bitLen = bitLen;
        nativeRef = new DigestRefWrapper(makeNative(bitLen));
        reset();
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public SHA3NativeDigest(int bitLen)
    {
        this(bitLen, CryptoServicePurpose.ANY);
    }

    public SHA3NativeDigest()
    {
        this(CryptoServicePurpose.ANY);
    }

    public SHA3NativeDigest(SHA3NativeDigest src)
    {

        this(CryptoServicePurpose.ANY);

        byte[] state = src.getEncodedState();

        restoreFullState(nativeRef.getReference(), state, 0);
    }

    public SHA3NativeDigest(byte[] encoded, CryptoServicePurpose purpose)
    {
        this(purpose);
        restoreFullState(nativeRef.getReference(), encoded, 0);
    }

    public SHA3NativeDigest(byte[] encoded)
    {
        this();
        restoreFullState(nativeRef.getReference(), encoded, 0);
    }


    SHA3NativeDigest restoreState(byte[] state, int offset)
    {
        synchronized (this)
        {
            restoreFullState(nativeRef.getReference(), state, offset);
            return this;
        }
    }

    //
    // ----------------------- End Testing only methods.
    //

    @Override
    public String getAlgorithmName()
    {

        return "SHA3-" + bitLen;
    }

    @Override
    public int getDigestSize()
    {
        synchronized (this)
        {
            return getDigestSize(nativeRef.getReference());
        }
    }


    @Override
    public void update(byte in)
    {
        synchronized (this)
        {
            update(nativeRef.getReference(), in);
        }
    }


    @Override
    public void update(byte[] input, int inOff, int len)
    {
        synchronized (this)
        {
            update(nativeRef.getReference(), input, inOff, len);
        }
    }


    @Override
    public int doFinal(byte[] output, int outOff)
    {
        synchronized (this)
        {
            int i = doFinal(nativeRef.getReference(), output, outOff);
            reset();
            return i;
        }
    }


    @Override
    public void reset()
    {
        synchronized (this)
        {
            reset(nativeRef.getReference());
        }
    }


    @Override
    public int getByteLength()
    {
        synchronized (this)
        {
            return getByteLength(nativeRef.getReference());
        }
    }


    @Override
    public Memoable copy()
    {
        return new SHA3NativeDigest(this);
    }

    @Override
    public void reset(Memoable other)
    {
        synchronized (this)
        {
            SHA3NativeDigest dig = (SHA3NativeDigest) other;
            restoreFullState(nativeRef.getReference(), dig.getEncodedState(), 0);
        }
    }


    public byte[] getEncodedState()
    {
        synchronized (this)
        {
            int l = encodeFullState(nativeRef.getReference(), null, 0);
            byte[] state = new byte[l];
            encodeFullState(nativeRef.getReference(), state, 0);
            return state;
        }
    }


    void restoreFullState(byte[] encoded, int offset)
    {
        synchronized (this)
        {
            restoreFullState(nativeRef.getReference(), encoded, offset);
        }
    }


    @Override
    public String toString()
    {
        return "SHA3[Native]()";
    }

    static native long makeNative(int bitLen);

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
            super(reference, "SHA3");
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}






