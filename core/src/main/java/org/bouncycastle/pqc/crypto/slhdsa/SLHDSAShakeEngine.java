package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

class SLHDSAShakeEngine
    extends SLHDSAEngine
{
    private final Xof treeDigest;
    private final Xof maskDigest;

    public SLHDSAShakeEngine(int n, int w, int d, int a, int k, int h)
    {
        super(n, w, d, a, k, h);

        this.treeDigest = SHAKEDigest.newInstance(256);
        this.maskDigest = SHAKEDigest.newInstance(256);
    }

    void init(byte[] pkSeed)
    {

    }

    byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1)
    {
        byte[] mTheta = m1;

        byte[] rv = new byte[N];

        treeDigest.update(pkSeed, 0, pkSeed.length);
        treeDigest.update(adrs.value, 0, adrs.value.length);
        treeDigest.update(mTheta, 0, mTheta.length);
        treeDigest.doFinal(rv, 0, rv.length);

        return rv;
    }

    byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
    {
        byte[] rv = new byte[N];

        treeDigest.update(pkSeed, 0, pkSeed.length);
        treeDigest.update(adrs.value, 0, adrs.value.length);

        treeDigest.update(m1, 0, m1.length);
        treeDigest.update(m2, 0, m2.length);

        treeDigest.doFinal(rv, 0, rv.length);

        return rv;
    }

    IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] msgPrefix, byte[] msg)
    {
        int forsMsgBytes = ((A * K) + 7) / 8;
        int leafBits = H / D;
        int treeBits = H - leafBits;
        int leafBytes = (leafBits + 7) / 8;
        int treeBytes = (treeBits + 7) / 8;
        int m = forsMsgBytes + leafBytes + treeBytes;
        byte[] out = new byte[m];

        treeDigest.update(R, 0, R.length);
        treeDigest.update(pkSeed, 0, pkSeed.length);
        treeDigest.update(pkRoot, 0, pkRoot.length);
        if (msgPrefix != null)
        {
            treeDigest.update(msgPrefix, 0, msgPrefix.length);
        }
        treeDigest.update(msg, 0, msg.length);
        treeDigest.doFinal(out, 0, out.length);

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

    byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m)
    {
        byte[] mTheta = m;

        byte[] rv = new byte[N];

        treeDigest.update(pkSeed, 0, pkSeed.length);
        treeDigest.update(adrs.value, 0, adrs.value.length);
        treeDigest.update(mTheta, 0, mTheta.length);
        treeDigest.doFinal(rv, 0, rv.length);

        return rv;
    }

    byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs)
    {
        treeDigest.update(pkSeed, 0, pkSeed.length);
        treeDigest.update(adrs.value, 0, adrs.value.length);
        treeDigest.update(skSeed, 0, skSeed.length);

        byte[] prf = new byte[N];
        treeDigest.doFinal(prf, 0, N);
        return prf;
    }

    public byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] msgPrefix, byte[] msg)
    {
        treeDigest.update(prf, 0, prf.length);
        treeDigest.update(randomiser, 0, randomiser.length);
        if (msgPrefix != null)
        {
            treeDigest.update(msgPrefix, 0, msgPrefix.length);
        }
        treeDigest.update(msg, 0, msg.length);

        byte[] out = new byte[N];
        treeDigest.doFinal(out, 0, out.length);
        return out;
    }

    protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m)
    {
        byte[] mask = new byte[m.length];
        maskDigest.update(pkSeed, 0, pkSeed.length);
        maskDigest.update(adrs.value, 0, adrs.value.length);
        maskDigest.doFinal(mask, 0, mask.length);
        Bytes.xorTo(m.length, m, mask);
        return mask;
    }

    protected byte[] bitmask(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
    {
        byte[] mask = new byte[m1.length + m2.length];
        maskDigest.update(pkSeed, 0, pkSeed.length);
        maskDigest.update(adrs.value, 0, adrs.value.length);
        maskDigest.doFinal(mask, 0, mask.length);
        Bytes.xorTo(m1.length, m1, mask);
        Bytes.xorTo(m2.length, m2, 0, mask, m1.length);
        return mask;
    }
}
