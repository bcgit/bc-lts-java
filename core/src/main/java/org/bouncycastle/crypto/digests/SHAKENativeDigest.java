package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;
import org.bouncycastle.util.encoders.Hex;

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
        restoreFullState(nativeRef.getReference(), state, offset);
        return this;
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
        return getDigestSize(nativeRef.getReference());
    }


    @Override
    public void update(byte in)
    {
        update(nativeRef.getReference(), in);
    }


    @Override
    public void update(byte[] input, int inOff, int len)
    {
        update(nativeRef.getReference(), input, inOff, len);
    }


    @Override
    public int doFinal(byte[] output, int outOff)
    {
        int i = doFinal(nativeRef.getReference(), output, outOff, getDigestSize(nativeRef.getReference()));
        reset();
        return i;
    }

    @Override
    public int doFinal(byte[] out, int outOff, int outLen)
    {
        int i = doFinal(nativeRef.getReference(),out,outOff,outLen);
        reset();
        return i;
    }

    @Override
    public int doOutput(byte[] out, int outOff, int outLen)
    {
        int i = doFinal(nativeRef.getReference(),out,outOff,outLen);
        reset();
        return i;
    }


    @Override
    public void reset()
    {
        reset(nativeRef.getReference());
    }


    @Override
    public int getByteLength()
    {
        return getByteLength(nativeRef.getReference());
    }


    @Override
    public Memoable copy()
    {
        return new SHAKENativeDigest(this);
    }

    @Override
    public void reset(Memoable other)
    {
        SHAKENativeDigest dig = (SHAKENativeDigest) other;
        restoreFullState(nativeRef.getReference(), dig.getEncodedState(), 0);
    }


    public byte[] getEncodedState()
    {
        int l = encodeFullState(nativeRef.getReference(), null, 0);
        byte[] state = new byte[l];
        encodeFullState(nativeRef.getReference(), state, 0);
        return state;
    }


    void restoreFullState(byte[] encoded, int offset)
    {
        restoreFullState(nativeRef.getReference(), encoded, offset);
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






