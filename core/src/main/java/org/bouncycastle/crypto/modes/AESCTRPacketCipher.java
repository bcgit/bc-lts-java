package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESCTRPacketCipher
    extends PacketCipherEngine
{
    public static AESCTRPacketCipher makeInstance()
    {
        return new AESCTRPacketCipher();
    }

    private AESCTRPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        return 0;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        BlockCipher cipher = new AESEngine();
        int blockSize = cipher.getBlockSize();
        byte[] IV;
        byte[] counter = new byte[blockSize];
        int[] counterIn = new int[4];
        int[] counterOut = new int[4];
        int ROUNDS;
        int[][] workingKey;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            IV = Arrays.clone(ivParam.getIV());

            if (blockSize < IV.length)
            {
                throw new IllegalArgumentException("CTR/SIC mode requires IV no greater than: " + blockSize + " bytes.");
            }

            int maxCounterSize = Math.min(8, blockSize >> 1);

            if (blockSize - IV.length > maxCounterSize)
            {
                throw new IllegalArgumentException("CTR/SIC mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");
            }

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }

            Arrays.fill(counter, (byte)0);
            System.arraycopy(IV, 0, counter, 0, IV.length);

            cipher.reset();
            int keyLen = ((KeyParameter)ivParam.getParameters()).getKey().length;
            int KC = keyLen >>> 2;
            ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
            workingKey = generateWorkingKey(((KeyParameter)ivParam.getParameters()).getKey(), KC, ROUNDS);
        }
        else
        {
            throw new IllegalArgumentException("CTR/SIC mode requires ParametersWithIV");
        }
        littleEndianToInt4(counter, 0, counterIn);
        byte[] s = Arrays.clone(S);
        int blockCount = len >>> 4;
        int inIndex = inOff;
        int outIndex = outOff;
        for (int k = 0; k < blockCount; ++k)
        {
            ctrProcessBlock(counter, counterIn, counterOut, input, inIndex, output, outIndex, workingKey, s, ROUNDS);
            inIndex += BLOCK_SIZE;
            outIndex += BLOCK_SIZE;
        }
        System.arraycopy(input, inIndex, counter, 0, len + inOff - inIndex);
        encryptBlock(counterIn, counterOut, workingKey, s, ROUNDS);
        int4XorLittleEndian(counterOut, counter, 0);
        for (int i = 0; i < len + inOff - inIndex; ++i)
        {
            output[outIndex + i] = counter[i];
        }

//        int4XorLittleEndianTail(counterOut, input, inIndex, len + inOff - inIndex);
//        int4ToLittleEndianTail(counterOut, output, outIndex, len + inOff - inIndex);
        return len;
    }

    private void ctrProcessBlock(byte[] counter, int[] counterIn, int[] counterOut, byte[] in, int inOff, byte[] out, int outOff,
                                 int[][] workingkeys, byte[] s, int ROUNDS)
    {
        encryptBlock(counterIn, counterOut, workingkeys, s, ROUNDS);
        int i = counter.length;
        while (--i >= 0)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
        i >>= 2;
        for (int j = 0; j < i; ++j)
        {
            counterIn[3 - j] = Pack.littleEndianToInt(counter, 12 - (j << 2));
        }
        int4XorLittleEndian(counterOut, in, inOff);
        int4ToLittleEndian(counterOut, out, outOff);
    }
}
