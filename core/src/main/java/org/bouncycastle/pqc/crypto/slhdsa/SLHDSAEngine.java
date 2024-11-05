package org.bouncycastle.pqc.crypto.slhdsa;

abstract class SLHDSAEngine
{
    final int N;

    final int WOTS_W;
    final int WOTS_LOGW;
    final int WOTS_LEN;
    final int WOTS_LEN1;
    final int WOTS_LEN2;

    final int D;
    final int A; // FORS_HEIGHT
    final int K; // FORS_TREES
    final int H; // FULL_HEIGHT
    final int H_PRIME;  // H / D

    final int T; // T = 1 << A

    public SLHDSAEngine(int n, int w, int d, int a, int k, int h)
    {
        this.N = n;

        /* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
        if (w == 16)
        {
            WOTS_LOGW = 4;
            WOTS_LEN1 = (8 * N / WOTS_LOGW);
            if (N <= 8)
            {
                WOTS_LEN2 = 2;
            }
            else if (N <= 136)
            {
                WOTS_LEN2 = 3;
            }
            else if (N <= 256)
            {
                WOTS_LEN2 = 4;
            }
            else
            {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        }
        else if (w == 256)
        {
            WOTS_LOGW = 8;
            WOTS_LEN1 = (8 * N / WOTS_LOGW);
            if (N <= 1)
            {
                WOTS_LEN2 = 1;
            }
            else if (N <= 256)
            {
                WOTS_LEN2 = 2;
            }
            else
            {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
        }
        else
        {
            throw new IllegalArgumentException("wots_w assumed 16 or 256");
        }
        this.WOTS_W = w;
        this.WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

        this.D = d;
        this.A = a;
        this.K = k;
        this.H = h;
        this.H_PRIME = h / d;
        this.T = 1 << a;
    }

    abstract void init(byte[] pkSeed);

    abstract byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1);

    abstract byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2);

    abstract IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] msgPrefix, byte[] msg);

    abstract byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m);

    abstract byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs);

    abstract byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] msgPrefix, byte[] msg);
}
