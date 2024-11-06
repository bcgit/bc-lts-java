package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

class SLHDSASha2NativeEngine
        extends SLHDSAEngine
{
    private SLHDSASha2NativeEngine.SLHDSARefWrapper ref;

    private final HMac treeHMac;
    private final byte[] hmacBuf;
    private final byte[] msgDigestBuf;
    private final int bl;
    private final byte[] sha256Buf = new byte[32];


    protected SLHDSASha2NativeEngine(int n, int w, int d, int a, int k, int h)
    {
        super(n, w, d, a, k, h);

        ref = new SLHDSARefWrapper(makeInstance());

        assert n == 16;

        this.treeHMac = new HMac(SHA256Digest.newInstance());
        this.bl = 64;
        this.hmacBuf = new byte[treeHMac.getMacSize()];
        this.msgDigestBuf = new byte[32];
    }

    void init(byte[] pkSeed)
    {

        final byte[] padding2 = new byte[bl];
        initMemoStates(ref.getReference(), pkSeed, padding2, bl - N, 64 - pkSeed.length);

    }

    static native void initMemoStates(long ref, byte[] pkSeed, byte[] padding, int padLen1, int padLen2);


    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1)
    {
        byte[] compressedADRS = compressedADRS(adrs);
        return sha256DigestAndReturnRange(ref.getReference(), true, sha256Buf, new byte[N], compressedADRS, m1, null, null);
    }


    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
    {
        byte[] compressedADRS = compressedADRS(adrs);
        return msgDigestAndReturnRange(ref.getReference(), true, msgDigestBuf, new byte[N], compressedADRS, m1, m2, null, null);
    }

    IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] msgPrefix, byte[] msg)
    {
        int forsMsgBytes = ((A * K) + 7) / 8;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) / 8;
        int treeBytes = (treeBits + 7) / 8;
        int m = forsMsgBytes + leafBytes + treeBytes;
        byte[] out = new byte[m];
        byte[] dig = new byte[32];

        msgDigestAndReturnRange(ref.getReference(), false, dig, null, prf, pkSeed, pkRoot, msgPrefix, msg);


        out = bitmask(Arrays.concatenate(prf, pkSeed, dig), out);

        // tree index
        // currently, only indexes up to 64 bits are supported
        byte[] treeIndexBuf = new byte[8];
        System.arraycopy(out, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
        long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0);
        treeIndex &= (~0L) >>> (64 - treeBits);

        byte[] leafIndexBuf = new byte[4];
        System.arraycopy(out, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);

        int leafIndex = Pack.bigEndianToInt(leafIndexBuf, 0);
        leafIndex &= (~0) >>> (32 - leafBits);

        return new IndexedDigest(treeIndex, leafIndex, Arrays.copyOfRange(out, 0, forsMsgBytes));
    }

    public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m)
    {
        byte[] compressedADRS = compressedADRS(adrs);
        msgDigestAndReturnRange(ref.getReference(), true, msgDigestBuf, new byte[N], compressedADRS, m, null, null, null);
        return Arrays.copyOfRange(msgDigestBuf, 0, N);
    }

    byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs)
    {
        int n = skSeed.length;
        byte[] compressedADRS = compressedADRS(adrs);
        return sha256DigestAndReturnRange(ref.getReference(), true, sha256Buf, new byte[n], compressedADRS, skSeed, null, null);
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] msgPrefix, byte[] msg)
    {
        treeHMac.init(new KeyParameter(prf));
        treeHMac.update(randomiser, 0, randomiser.length);
        if (msgPrefix != null)
        {
            treeHMac.update(msgPrefix, 0, msgPrefix.length);
        }
        treeHMac.update(msg, 0, msg.length);
        treeHMac.doFinal(hmacBuf, 0);

        return Arrays.copyOfRange(hmacBuf, 0, N);
    }

    private byte[] compressedADRS(ADRS adrs)
    {
        byte[] rv = new byte[22];
        System.arraycopy(adrs.value, ADRS.OFFSET_LAYER + 3, rv, 0, 1); // LSB layer address
        System.arraycopy(adrs.value, ADRS.OFFSET_TREE + 4, rv, 1, 8); // LS 8 bytes Tree address
        System.arraycopy(adrs.value, ADRS.OFFSET_TYPE + 3, rv, 9, 1); // LSB type
        System.arraycopy(adrs.value, 20, rv, 10, 12);

        return rv;
    }

    protected byte[] bitmask(byte[] key, byte[] m)
    {
        byte[] mask = new byte[m.length];
        bitmask(ref.getReference(), key, mask, m, null, null, null);
        return mask;
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
            SLHDSASha2NativeEngine.dispose(reference);
        }
    }

    private class SLHDSARefWrapper
            extends NativeReference
    {

        public SLHDSARefWrapper(long reference)
        {
            super(reference, "SLHDSA_SHA256_NATIVE");
        }

        @Override
        public Runnable createAction()
        {
            return new SLHDSASha2NativeEngine.Disposer(reference);
        }
    }

    @Override
    public String toString()
    {
        return "SLHDSA[Native](SHA252[Native]())";
    }


    static native long makeInstance();

    static native void dispose(long ref);

    /**
     * @param ref     reference
     * @param useMemo Use memo
     * @param digest  The full digest
     * @param range   The partial digest
     * @param in0     input 0, may be null
     * @param in1     input 1, may be null
     * @param in2     input 2, may be null
     * @param in3     input 3, may be null
     */
    static native byte[] sha256DigestAndReturnRange(
            long ref,
            boolean useMemo,
            byte[] digest,
            byte[] range,
            byte[] in0,
            byte[] in1,
            byte[] in2,
            byte[] in3);


    /**
     * @param digest full digest result
     * @param in0    input 0, may be null
     * @param in1    input 1, may be null
     * @param in2    input 2, may be null
     * @param in3    input 3, may be null
     * @return a new byte[] array or null if returnStart and returnLength are -1;
     */
    static native byte[] msgDigestAndReturnRange(
            long ref,
            boolean useMemo,
            byte[] digest,
            byte[] range,
            byte[] in0,
            byte[] in1,
            byte[] in2,
            byte[] in3,
            byte[] in4);


    static native void bitmask(long ref, byte[] key, byte[] result, byte[] i0, byte[] i1, byte[] i2, byte[] i3);

}
