package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCBCPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESCBCPacketCipher
        extends AESPacketCipherEngine
        implements AESCBCModePacketCipher
{
    public static AESCBCModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CBC_PC))
        {
            return new AESNativeCBCPacketCipher();
        }

        return new AESCBCPacketCipher();
    }

    public AESCBCPacketCipher()
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
        boolean tail = (len & 15) != 0;
        int blockCount = (len >> 4) + (tail ? 1 : 0);
        if ((blockCount << 4) + outOff > output.length)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessage.OUTPUT_LENGTH));
        }

        byte[] iv;
        int[][] workingKey;
        byte[] s;
        int[] C = new int[4];
        int[] C2 = null;
        if (!encryption)
        {
            C2 = new int[4];
        }
        int ROUNDS;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) parameters;
            iv = ivParam.getIV().clone();
            if (iv.length != BLOCK_SIZE)
            {
                throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.CBC_IV_LENGTH));
            }
            KeyParameter params = (KeyParameter) ivParam.getParameters();
            // if null it's an IV changed only.
            if (params != null)
            {
                byte[] key = params.getKey();
                int keyLen = key.length;
                checkKeyLength(keyLen);
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;
                workingKey = generateWorkingKey(key, KC, ROUNDS, encryption);
                s = Arrays.clone(encryption ? S : Si);
            }
            else
            {
                throw PacketCipherException.from(new IllegalArgumentException("CBC cipher unitialized"));
            }
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CBC"));
        }
        int i, j;
        if (encryption)
        {
            C[0] = Pack.littleEndianToInt(iv, 0) ^ Pack.littleEndianToInt(input, inOff);
            C[1] = Pack.littleEndianToInt(iv, 4) ^ Pack.littleEndianToInt(input, inOff + 4);
            C[2] = Pack.littleEndianToInt(iv, 8) ^ Pack.littleEndianToInt(input, inOff + 8);
            C[3] = Pack.littleEndianToInt(iv, 12) ^ Pack.littleEndianToInt(input, inOff + 12);
            encryptBlock(C, workingKey, s, ROUNDS);
            int4ToLittleEndian(C, output, outOff);
            inOff += BLOCK_SIZE;
            outOff += BLOCK_SIZE;
            for (i = 1; i < len >> 4; ++i)
            {
                int4XorLittleEndian(C, input, inOff);
                encryptBlock(C, workingKey, s, ROUNDS);
                int4ToLittleEndian(C, output, outOff);
                inOff += BLOCK_SIZE;
                outOff += BLOCK_SIZE;
            }
            if (tail)
            {
                for (j = 0; j + inOff < len; ++j)
                {
                    output[j + outOff] = (byte) (input[inOff + j] ^ output[j + outOff - BLOCK_SIZE]);
                }
                encryptBlock(output, outOff, output, outOff, workingKey, s, ROUNDS);
            }
        }
        else
        {
            littleEndianToInt4(input, inOff, C);
            decryptBlock(C, C2, workingKey, s, ROUNDS);
            int4XorLittleEndian(C2, iv, 0);
            int4ToLittleEndian(C2, output, outOff);
            inOff += BLOCK_SIZE;
            outOff += BLOCK_SIZE;
            for (i = 1; i < blockCount; ++i)
            {
                int[] tmp = C2;
                C2 = C;
                C = tmp;
                littleEndianToInt4(input, inOff, C);
                decryptBlock(C, C2, workingKey, s, ROUNDS);
                int4ToLittleEndian(C2, output, outOff);
                inOff += BLOCK_SIZE;
                outOff += BLOCK_SIZE;
            }
            Arrays.fill(C2, 0);
        }
        for (int[] ints : workingKey)
        {
            Arrays.fill(ints, 0);
        }
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(C, 0);
        return blockCount << 4;
    }

    // public String toString()
    //    {
    //        return "CBC[Java](" + cipher.toString() + ")";
    //    }


    @Override
    public String toString()
    {
        return "CBC-PS[Java](AES[Java])";
    }
}
