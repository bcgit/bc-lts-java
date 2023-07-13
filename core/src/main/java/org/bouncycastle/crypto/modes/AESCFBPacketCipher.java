package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCFBPacketCipher
    extends PacketCipherEngine
{
    public static AESCFBPacketCipher newInstance()
    {
        return new AESCFBPacketCipher();
    }

    private AESCFBPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        return len;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        processPacketExceptionCheck(input, inOff, len, output, outOff);
        BlockCipher cipher = new AESEngine();
        byte[] cfbV = new byte[BLOCK_SIZE];
        byte[] cfbOutV = new byte[BLOCK_SIZE];
        byte[] inBuf = new byte[BLOCK_SIZE];
        byte[] iv;
        int[][] workingKey = null;
        byte[] s = null;
        int ROUNDS = 0;
        int byteCount = 0;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            iv = ivParam.getIV().clone();
            //reset
            System.arraycopy(iv, 0, cfbV, cfbV.length - iv.length, iv.length);
            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
                byte[] key = ((KeyParameter)ivParam.getParameters()).getKey();
                int keyLen = key.length;
                if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
                {
                    throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.AES_KEY_LENGTH));
                }
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;
                workingKey = generateWorkingKey(key, KC, ROUNDS, encryption);
                s = Arrays.clone(encryption ? S : Si);
            }
        }
        int inStart = inOff;
        int inEnd = inOff + len;
        int outStart = outOff;
        int blockCount = (len >>> 4) + (((len & 15) != 0) ? 1 : 0);
        if (encryption)
        {
            for (int i = 0; i < blockCount; ++i)
            {
                encryptBlock(cfbV, cfbV, workingKey, s, ROUNDS);
                if (i != blockCount - 1)
                {
                    for (int j = 0; j < BLOCK_SIZE; ++j)
                    {
                        cfbV[j] = (byte)(cfbV[j] ^ input[inStart++]);
                        output[outStart++] = cfbV[j];
                    }
                }
                else
                {
                    for (int j = 0; inStart < len; ++j)
                    {
                        output[outStart++] = (byte)(cfbV[j] ^ input[inStart++]);
                    }
                }
            }
        }
        else
        {
//            for (int i = 0; i < blockCount; ++i)
//            {
//                if (i == 0)
//                {
//                    decryptBlock(cfbV, 0, cfbV, 0, workingKey, s, ROUNDS);
//                }
//                else
//                {
//                    decryptBlock(input, inStart, cfbV, 0, workingKey, s, ROUNDS);
//                }
//
//                if (i != blockCount - 1)
//                {
//                    for (int j = 0; j < BLOCK_SIZE; ++j)
//                    {
//                        output[outStart++] = (byte)(cfbV[j] ^ input[inStart++]);
//                        output[outStart++] = cfbV[j];
//                    }
//                }
//                else
//                {
//                    for (int j = 0; inStart < len; ++j)
//                    {
//                        output[outStart++] = (byte)(cfbV[j] ^ input[inStart++]);
//                    }
//                }
//            }
            while (inStart < inEnd)
            {
                if (byteCount == 0)
                {
                    cipher.processBlock(cfbV, 0, cfbOutV, 0);
                }
                inBuf[byteCount] = input[inStart];
                byte rv = (byte)(cfbOutV[byteCount++] ^ input[inStart++]);
                if (byteCount == BLOCK_SIZE)
                {
                    byteCount = 0;
                    System.arraycopy(inBuf, 0, cfbV, 0, BLOCK_SIZE);
                }
                output[outStart++] = rv;
            }
        }

        return len;
    }

    @Override
    public String toString()
    {
        return "CFB Packet Cipher";
    }
}
