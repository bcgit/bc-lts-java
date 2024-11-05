package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

class SLHDSASha2Engine
    extends SLHDSAEngine
{
    private final HMac treeHMac;
    private final MGF1BytesGenerator mgf1;
    private final byte[] hmacBuf;
    private final Digest msgDigest;
    private final byte[] msgDigestBuf;
    private final int bl;
    private final Digest sha256 = SHA256Digest.newInstance();
    private final byte[] sha256Buf = new byte[sha256.getDigestSize()];

    private Memoable msgMemo;
    private Memoable sha256Memo;

    public SLHDSASha2Engine(int n, int w, int d, int a, int k, int h)
    {
        super(n, w, d, a, k, h);
        if (n == 16)
        {
            this.msgDigest = SHA256Digest.newInstance();
            this.treeHMac = new HMac(SHA256Digest.newInstance());
            this.mgf1 = new MGF1BytesGenerator(SHA256Digest.newInstance());
            this.bl = 64;
        }
        else
        {
            this.msgDigest = SHA512Digest.newInstance();
            this.treeHMac = new HMac(SHA512Digest.newInstance());
            this.mgf1 = new MGF1BytesGenerator(SHA512Digest.newInstance());
            this.bl = 128;
        }

        this.hmacBuf = new byte[treeHMac.getMacSize()];
        this.msgDigestBuf = new byte[msgDigest.getDigestSize()];
    }

    void init(byte[] pkSeed)
    {
        final byte[] padding = new byte[bl];

        msgDigest.update(pkSeed, 0, pkSeed.length);
        msgDigest.update(padding, 0, bl - N); // toByte(0, 64 - n)
        msgMemo = ((Memoable)msgDigest).copy();

        msgDigest.reset();

        sha256.update(pkSeed, 0, pkSeed.length);
        sha256.update(padding, 0, 64 - pkSeed.length); // toByte(0, 64 - n)
        sha256Memo = ((Memoable)sha256).copy();

        sha256.reset();
    }

    public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1)
    {
        byte[] compressedADRS = compressedADRS(adrs);

        ((Memoable)sha256).reset(sha256Memo);

        sha256.update(compressedADRS, 0, compressedADRS.length);
        sha256.update(m1, 0, m1.length);
        sha256.doFinal(sha256Buf, 0);

        return Arrays.copyOfRange(sha256Buf, 0, N);
    }

    public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2)
    {
        byte[] compressedADRS = compressedADRS(adrs);

        ((Memoable)msgDigest).reset(msgMemo);

        msgDigest.update(compressedADRS, 0, compressedADRS.length);

        msgDigest.update(m1, 0, m1.length);
        msgDigest.update(m2, 0, m2.length);

        msgDigest.doFinal(msgDigestBuf, 0);

        return Arrays.copyOfRange(msgDigestBuf, 0, N);
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
        byte[] dig = new byte[msgDigest.getDigestSize()];

        msgDigest.update(prf, 0, prf.length);
        msgDigest.update(pkSeed, 0, pkSeed.length);
        msgDigest.update(pkRoot, 0, pkRoot.length);
        if (msgPrefix != null)
        {
            msgDigest.update(msgPrefix, 0, msgPrefix.length);
        }
        msgDigest.update(msg, 0, msg.length);
        msgDigest.doFinal(dig, 0);

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

        ((Memoable)msgDigest).reset(msgMemo);

        msgDigest.update(compressedADRS, 0, compressedADRS.length);
        msgDigest.update(m, 0, m.length);
        msgDigest.doFinal(msgDigestBuf, 0);

        return Arrays.copyOfRange(msgDigestBuf, 0, N);
    }

    byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs)
    {
        int n = skSeed.length;

        ((Memoable)sha256).reset(sha256Memo);

        byte[] compressedADRS = compressedADRS(adrs);

        sha256.update(compressedADRS, 0, compressedADRS.length);
        sha256.update(skSeed, 0, skSeed.length);
        sha256.doFinal(sha256Buf, 0);

        return Arrays.copyOfRange(sha256Buf, 0, n);
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
        mgf1.init(new MGFParameters(key));
        mgf1.generateBytes(mask, 0, mask.length);
        Bytes.xorTo(m.length, m, mask);
        return mask;
    }

    protected byte[] bitmask(byte[] key, byte[] m1, byte[] m2)
    {
        byte[] mask = new byte[m1.length + m2.length];
        mgf1.init(new MGFParameters(key));
        mgf1.generateBytes(mask, 0, mask.length);
        Bytes.xorTo(m1.length, m1, mask);
        Bytes.xorTo(m2.length, m2, 0, mask, m1.length);
        return mask;
    }

    protected byte[] bitmask256(byte[] key, byte[] m)
    {
        byte[] mask = new byte[m.length];
        MGF1BytesGenerator mgf1 = new MGF1BytesGenerator(new SHA256Digest());
        mgf1.init(new MGFParameters(key));
        mgf1.generateBytes(mask, 0, mask.length);
        Bytes.xorTo(m.length, m, mask);
        return mask;
    }
}
