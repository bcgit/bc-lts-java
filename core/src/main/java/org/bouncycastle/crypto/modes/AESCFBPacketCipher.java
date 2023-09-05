package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCFBPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCFBPacketCipher
        extends AESPacketCipherEngine
        implements AESCFBModePacketCipher
{
    public static AESCFBModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CFB_PC))
        {
            return new AESNativeCFBPacketCipher();
        }

        return new AESCFBPacketCipher();
    }

    protected AESCFBPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        if (encryption)
        {
            return ((len >> 4) + ((len & 15) != 0 ? 1 : 0)) << 4;
        }
        else
        {
            if ((len & 15) != 0)
            {
                throw new IllegalArgumentException(ExceptionMessage.AES_DECRYPTION_INPUT_LENGTH_INVALID);
            }
            return len;
        }
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
            throws PacketCipherException
    {
        processPacketExceptionCheck(input, inOff, len, output, outOff);
        if (outOff + len > output.length)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessage.OUTPUT_LENGTH));
        }
        if (!encryption && ((len & 15) != 0))
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.AES_DECRYPTION_INPUT_LENGTH_INVALID));
        }
        byte[] cfbV = new byte[BLOCK_SIZE];
        byte[] iv;
        int[][] workingKey;
        byte[] s;
        int ROUNDS;
        int C[] = new int[4];
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) parameters;
            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                byte[] key = ((KeyParameter) ivParam.getParameters()).getKey();
                int keyLen = key.length;
                checkKeyLength(keyLen);
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;
                workingKey = generateWorkingKey(key, KC, ROUNDS);
                s = Arrays.clone(S);
            }
            else
            {
                throw PacketCipherException.from(new IllegalArgumentException("CFB cipher unitialized"));
            }
            iv = Arrays.clone(ivParam.getIV());
            //reset
            if (iv.length < BLOCK_SIZE)
            {
                System.arraycopy(iv, 0, cfbV, cfbV.length - iv.length, iv.length);
            }
            else
            {
                cfbV = iv;
            }
            littleEndianToInt4(cfbV, 0, C);
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CFB"));
        }
        int inStart = inOff;
        int outStart = outOff;
        int blockCount = len >>> 4;
        if (encryption)
        {
            boolean tail = (len & 15) != 0;
            for (int i = 0; i < blockCount; ++i)
            {
                encryptBlock(C, workingKey, s, ROUNDS);
                int4XorLittleEndian(C, input, inStart);
                int4ToLittleEndian(C, output, outStart);
                inStart += BLOCK_SIZE;
                outStart += BLOCK_SIZE;
            }
            if (tail)
            {
                encryptBlock(C, workingKey, s, ROUNDS);
                int4XorLittleEndianTail(C, input, inStart, input.length - inStart);
                int4ToLittleEndian(C, output, outStart);
            }
        }
        else
        {
            for (int i = 0; i < blockCount; ++i)
            {
                encryptBlock(C, workingKey, s, ROUNDS);
                int4XorLittleEndian(C, input, inStart);
                int4ToLittleEndian(C, output, outStart);
                littleEndianToInt4(input, inStart, C);
                inStart += BLOCK_SIZE;
                outStart += BLOCK_SIZE;
            }
        }
        Arrays.fill(cfbV, (byte) 0);
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(C, 0);
        for (int[] ints : workingKey)
        {
            Arrays.fill(ints, 0);
        }

        return len;
    }

    @Override
    public String toString()
    {
        return "CFB-PS[Java](AES[Java])";
    }
}
