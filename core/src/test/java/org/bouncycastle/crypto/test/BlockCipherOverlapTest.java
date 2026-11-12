package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * AES ECB and CBC through processBlock() and processBlocks() with the output overlapping the input
 * in the same array, from behind and from ahead, must give the same result as separate buffers.
 * On the native variants these reach the native AES engine and CBC, which work through the buffers
 * in order and so need the input moved before an output ahead of it is written. Out of range
 * arguments must still be refused.
 */
public class BlockCipherOverlapTest
    extends SimpleTest
{
    private static final int IN_OFF = 23;
    private static final int[] OUT_OFFS = new int[]{ 0, 7, 16, 22, 23, 24, 30, 39, 40, 100, 150, 151 };

    private interface Factory
    {
        BlockCipher create();

        CipherParameters params(byte[] key, byte[] iv);
    }

    public String getName()
    {
        return "BlockCipherOverlap";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        long seed = random.nextLong();
        random.setSeed(seed);

        Factory[] factories = new Factory[]{
            new Factory()
            {
                public BlockCipher create()
                {
                    return AESEngine.newInstance();
                }

                public CipherParameters params(byte[] key, byte[] iv)
                {
                    return new KeyParameter(key);
                }
            },
            new Factory()
            {
                public BlockCipher create()
                {
                    return CBCBlockCipher.newInstance(AESEngine.newInstance());
                }

                public CipherParameters params(byte[] key, byte[] iv)
                {
                    return new ParametersWithIV(new KeyParameter(key), iv);
                }
            }
        };

        for (int f = 0; f != factories.length; f++)
        {
            for (int keyLen = 16; keyLen <= 32; keyLen += 8)
            {
                byte[] key = new byte[keyLen];
                byte[] iv = new byte[16];
                random.nextBytes(key);
                random.nextBytes(iv);
                CipherParameters params = factories[f].params(key, iv);

                int blocks = 1 + random.nextInt(8);
                byte[] input = new byte[blocks * 16];
                random.nextBytes(input);

                for (int dir = 0; dir != 2; dir++)
                {
                    boolean encrypt = dir == 0;
                    String label = factories[f].create().getAlgorithmName() + "/" + keyLen + (encrypt ? " encrypt" : " decrypt")
                        + " (seed " + seed + ")";

                    BlockCipher ref = factories[f].create();
                    ref.init(encrypt, params);
                    byte[] expected = new byte[input.length];
                    for (int i = 0; i != blocks; i++)
                    {
                        ref.processBlock(input, i * 16, expected, i * 16);
                    }
                    isTrue(label + ": transform is identity", !Arrays.areEqual(expected, input));

                    for (int o = 0; o != OUT_OFFS.length; o++)
                    {
                        int outOff = OUT_OFFS[o];

                        BlockCipher c = factories[f].create();
                        c.init(encrypt, params);
                        byte[] buf = new byte[Math.max(IN_OFF, outOff) + input.length];
                        System.arraycopy(input, 0, buf, IN_OFF, input.length);
                        if (c instanceof MultiBlockCipher)
                        {
                            ((MultiBlockCipher)c).processBlocks(buf, IN_OFF, blocks, buf, outOff);
                        }
                        else
                        {
                            fail(label + ": not a MultiBlockCipher");
                        }
                        check(label + " processBlocks, output at " + outOff, expected, buf, outOff);

                        // a block at a time, in place or with the output behind the input
                        if (outOff <= IN_OFF)
                        {
                            c = factories[f].create();
                            c.init(encrypt, params);
                            buf = new byte[IN_OFF + input.length];
                            System.arraycopy(input, 0, buf, IN_OFF, input.length);
                            for (int i = 0; i != blocks; i++)
                            {
                                c.processBlock(buf, IN_OFF + i * 16, buf, outOff + i * 16);
                            }
                            check(label + " processBlock, output at " + outOff, expected, buf, outOff);
                        }

                        // a single block overlapping itself
                        c = factories[f].create();
                        c.init(encrypt, params);
                        buf = new byte[Math.max(IN_OFF, outOff) + 16];
                        System.arraycopy(input, 0, buf, IN_OFF, 16);
                        c.processBlock(buf, IN_OFF, buf, outOff);
                        check(label + " single processBlock, output at " + outOff,
                            Arrays.copyOfRange(expected, 0, 16), buf, outOff);
                    }
                }

                checkRefused(factories[f], params, blocks);
            }
        }
    }

    private void check(String label, byte[] expected, byte[] buf, int outOff)
    {
        byte[] actual = Arrays.copyOfRange(buf, outOff, outOff + expected.length);
        if (!Arrays.areEqual(expected, actual))
        {
            fail(label + ": expected " + Hex.toHexString(expected) + " got " + Hex.toHexString(actual));
        }
    }

    private void checkRefused(Factory factory, CipherParameters params, int blocks)
    {
        int len = blocks * 16;
        int[][] bad = new int[][]{
            // inOff, blockCount, outOff, buffer length
            { -1, blocks, 16, len + 32 },
            { 0, -1, 16, len + 32 },
            { 0, blocks, -1, len + 32 },
            { Integer.MIN_VALUE, blocks, 16, len + 32 },
            { 0, Integer.MIN_VALUE, 16, len + 32 },
            { 0, Integer.MAX_VALUE, 16, len + 32 },
            { 0, Integer.MAX_VALUE / 16 + 1, 16, len + 32 },
            { 0, blocks, 17, len + 16 },        // output ahead of the input runs off the end
            { 1, blocks, 0, len },              // input runs off the end
        };

        for (int i = 0; i != bad.length; i++)
        {
            int inOff = bad[i][0];
            int blockCount = bad[i][1];
            int outOff = bad[i][2];
            byte[] buf = new byte[bad[i][3]];
            for (int j = 0; j != buf.length; j++)
            {
                buf[j] = (byte)j;
            }

            BlockCipher c = factory.create();
            c.init(true, params);
            try
            {
                ((MultiBlockCipher)c).processBlocks(buf, inOff, blockCount, buf, outOff);
                fail(c.getAlgorithmName() + " accepted inOff " + inOff + ", blockCount " + blockCount + ", outOff " + outOff);
            }
            catch (RuntimeException e)
            {
                // expected
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new BlockCipherOverlapTest());
    }
}
