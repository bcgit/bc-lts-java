package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCBCPacketCipher
    extends PacketCipherEngine
{
    public static AESCBCPacketCipher newInstance()
    {
        return new AESCBCPacketCipher();
    }

    private AESCBCPacketCipher()
    {

    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (encryption)
        {
            return (len >> 4) + ((len & 15) != 0 ? 1 : 0);
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
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {
        byte[] cbcV = new byte[BLOCK_SIZE];
        byte[] cbcNextV = new byte[BLOCK_SIZE];
        int[][] workingKey = null;
        byte[] s;
        int ROUNDS;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            byte[] iv = ivParam.getIV();

            if (iv.length != BLOCK_SIZE)
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }
            System.arraycopy(iv, 0, cbcV, 0, iv.length);
            Arrays.fill(cbcNextV, (byte)0);
            KeyParameter params = (KeyParameter)ivParam.getParameters();
            // if null it's an IV changed only.
            if (params != null)
            {
                byte[] key = params.getKey();
                int keyLen = key.length;
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;
                workingKey = generateWorkingKey(key, KC, ROUNDS, encryption);
                if (encryption)
                {
                    s = Arrays.clone(S);
                }
                else
                {
                    s = Arrays.clone(Si);
                }
            }
            else
            {
                throw new IllegalArgumentException();
            }
        }
        else
        {
            throw new IllegalArgumentException();
        }


        int resultLen = 0;
        int blockCount = (len >> 4) + ((len & 15) != 0 ? 1 : 0);
        for (int i = 0; i != blockCount; i++)
        {
            if (encryption)
            {
                if ((inOff + BLOCK_SIZE) > input.length)
                {
                    throw new DataLengthException("input buffer too short");
                }
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    cbcV[j] ^= input[inOff + j];
                }
                encryptBlock(cbcV, 0, output, outOff + resultLen, workingKey, s, ROUNDS);
                System.arraycopy(output, outOff + resultLen, cbcV, 0, cbcV.length);
                resultLen += BLOCK_SIZE;
            }
            else
            {
                if ((inOff + BLOCK_SIZE) > input.length)
                {
                    throw new DataLengthException("input buffer too short");
                }
                System.arraycopy(input, inOff, cbcNextV, 0, BLOCK_SIZE);
                decryptBlock(input, inOff, output, outOff + resultLen, workingKey, s, ROUNDS);
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    output[outOff + resultLen + j] ^= cbcV[j];
                }
                byte[] tmp;
                tmp = cbcV;
                cbcV = cbcNextV;
                cbcNextV = tmp;
                resultLen += BLOCK_SIZE;
            }
            inOff += BLOCK_SIZE;
        }
        return resultLen;
    }

}
