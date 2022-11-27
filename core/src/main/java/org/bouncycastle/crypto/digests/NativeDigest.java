package org.bouncycastle.crypto.digests;


import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

public abstract class NativeDigest
        implements ExtendedDigest, Memoable, EncodableDigest
{

    protected DigestRefWrapper nativeRef = null;
    protected final CryptoServicePurpose purpose;

    protected NativeDigest(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
    }

    protected native long makeNative(int i);

    protected native void destroy(long nativeRef);

    protected native int getDigestSize(long nativeRef);

    protected native void update(long nativeRef, byte in);

    protected native void update(long nativeRef, byte[] in, int inOff, int len);

    protected native int doFinal(long nativeRef, byte[] out, int outOff);

    protected native void reset(long nativeRef);

    protected native int getByteLength(long nativeRef);

    protected native void setState(long nativeRef, byte[] state);

    protected native byte[] getState(long nativeRef);

    private static native void fromEncoded(long reference, byte[] encoded);


    /**
     * SHA256 implementation.
     */
    static class SHA256Native
            extends NativeDigest implements SavableDigest
    {

        SHA256Native(CryptoServicePurpose purpose)
        {
            super(purpose);
            CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
            reset();
        }

        SHA256Native(SHA256Native src)
        {
            this(src.purpose);
            nativeRef = new DigestRefWrapper(makeNative(1));
            byte[] state = src.getState(src.nativeRef.getReference());
            setState(nativeRef.getReference(), state);
        }

        SHA256Native()
        {
            this(CryptoServicePurpose.ANY);
            nativeRef = new DigestRefWrapper(makeNative(1));
        }

        SHA256Native(byte[] encoded)
        {
            this();
            fromEncoded(nativeRef.getReference(), encoded);
        }


        @Override
        public String getAlgorithmName()
        {
            return "SHA-256";
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
            if (input == null)
            {
                throw new IllegalArgumentException("input is null");
            }

            if (inOff < 0)
            {
                throw new IllegalArgumentException("inOff is negative");
            }

            if (len < 0)
            {
                throw new IllegalArgumentException("len is negative");
            }

            if (inOff + len > input.length)
            {
                throw new IllegalArgumentException("inOff + len exceeds input length");
            }


            update(nativeRef.getReference(), input, inOff, len);
        }


        @Override
        public int doFinal(byte[] out, int outOff)
        {
            if (out == null)
            {
                throw new IllegalArgumentException("out is null");
            }
            if (outOff < 0)
            {
                throw new IllegalArgumentException("outOff is negative");
            }

            if (outOff > out.length)
            {
                throw new IllegalArgumentException("outOff exceeds out length");
            }

            return doFinal(nativeRef.getReference(), out, outOff);
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
            return new SHA256Native(this);
        }

        @Override
        public void reset(Memoable other)
        {
            SHA256Native dig = (SHA256Native) other;
            setState(nativeRef.getReference(), dig.getState(dig.nativeRef.getReference()));
        }

        protected CryptoServiceProperties cryptoServiceProperties()
        {
            return Utils.getDefaultProperties(this, 256, purpose);
        }

        @Override
        public byte[] getEncodedState()
        {
            return getState(nativeRef.getReference());
        }
    }


    private class Disposer
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

    private class DigestRefWrapper
            extends NativeReference
    {

        public DigestRefWrapper(long reference)
        {
            super(reference);
        }

        @Override
        public Runnable createAction()
        {
            return new Disposer(reference);
        }
    }

}



