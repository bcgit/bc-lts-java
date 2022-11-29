package org.bouncycastle.crypto.digests;


import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

public abstract class NativeDigest
        implements ExtendedDigest, Memoable, EncodableDigest, NativeService
{

    protected DigestRefWrapper nativeRef = null;
    protected final CryptoServicePurpose purpose;

    NativeDigest(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
    }

    native long makeNative(int i);

    static native void destroy(long nativeRef);

    native int getDigestSize(long nativeRef);

    native void update(long nativeRef, byte in);

    native void update(long nativeRef, byte[] in, int inOff, int len);

    native int doFinal(long nativeRef, byte[] out, int outOff);

    native void reset(long nativeRef);

    native int getByteLength(long nativeRef);

    native int encodeFullState(long nativeRef, byte[] buffer, int offset);

    native void restoreFullState(long reference, byte[] encoded, int offset);


    /**
     * SHA256 implementation.
     */
    static class SHA256Native
            extends NativeDigest implements SavableDigest
    {

        SHA256Native(CryptoServicePurpose purpose)
        {
            super(purpose);
            nativeRef = new DigestRefWrapper(makeNative(1));
            CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
            reset();
        }

        SHA256Native(SHA256Native src)
        {
            this(src.purpose);
            byte[] state = src.getEncodedState();
            restoreFullState(nativeRef.getReference(), state, 0);
        }

        SHA256Native()
        {
            this(CryptoServicePurpose.ANY);
        }

        SHA256Native(byte[] encodedState)
        {
            this(CryptoServicePurpose.values()[encodedState[encodedState.length - 1]]);
            restoreFullState(nativeRef.getReference(), encodedState, 0);
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
        public int doFinal(byte[] output, int outOff)
        {
            if (output == null)
            {
                throw new IllegalArgumentException("output is null");
            }
            if (outOff < 0)
            {
                throw new IllegalArgumentException("outOff is negative");
            }

            if (outOff > output.length)
            {
                throw new IllegalArgumentException("outOff exceeds output length");
            }

            if (output.length < getDigestSize() + outOff)
            {
                throw new IllegalArgumentException("output at offset too small for digest result");
            }

            return doFinal(nativeRef.getReference(), output, outOff);
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
            restoreFullState(nativeRef.getReference(),dig.getEncodedState(),0);
        }

        protected CryptoServiceProperties cryptoServiceProperties()
        {
            return Utils.getDefaultProperties(this, 256, purpose);
        }

        @Override
        public byte[] getEncodedState()
        {
            int l = encodeFullState(nativeRef.getReference(), null, 0);
            byte[] state = new byte[l + 1];
            state[state.length - 1] = (byte) purpose.ordinal();
            encodeFullState(nativeRef.getReference(), state, 0);
            return state;
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
            NativeDigest.destroy(reference);
        }
    }

    private static class DigestRefWrapper
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



