package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
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
        BlockCipher cipher = new AESEngine();
        int blockSize = cipher.getBlockSize();
        byte[] IV = new byte[blockSize];
        byte[] cbcV = new byte[blockSize];
        byte[] cbcNextV = new byte[blockSize];
        int[][] workingKey = null;
        byte[] s;
        int ROUNDS;
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            byte[] iv = ivParam.getIV();

            if (iv.length != blockSize)
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }
            System.arraycopy(iv, 0, IV, 0, iv.length);
            System.arraycopy(IV, 0, cbcV, 0, IV.length);
            Arrays.fill(cbcNextV, (byte)0);
            KeyParameter params = (KeyParameter)ivParam.getParameters();
            // if null it's an IV changed only.
            if (params != null)
            {
                cipher.init(encryption, ivParam.getParameters());
                byte[] key = params.getKey();
                int keyLen = key.length;
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;
                workingKey = generateWorkingKey(key, KC, ROUNDS);
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
                if ((inOff + blockSize) > input.length)
                {
                    throw new DataLengthException("input buffer too short");
                }
                /*
                 * XOR the cbcV and the input,
                 * then encrypt the cbcV
                 */
                for (int j = 0; j < blockSize; j++)
                {
                    cbcV[j] ^= input[inOff + j];
                }

                encryptBlock(cbcV, 0, output, outOff + resultLen, workingKey, s, ROUNDS);
                //int length = cipher.processBlock(cbcV, 0, output, outOff + resultLen);

                /*
                 * copy ciphertext to cbcV
                 */
                System.arraycopy(output, outOff + resultLen, cbcV, 0, cbcV.length);
                resultLen += BLOCK_SIZE;
            }
            else
            {
                if ((inOff + blockSize) > input.length)
                {
                    throw new DataLengthException("input buffer too short");
                }

                System.arraycopy(input, inOff, cbcNextV, 0, blockSize);

                int length = cipher.processBlock(input, inOff, output, outOff + resultLen);
                decryptBlock(input, inOff, output, outOff + resultLen, workingKey, s, ROUNDS);
                /*
                 * XOR the cbcV and the output
                 */
                for (int j = 0; j < blockSize; j++)
                {
                    output[outOff + resultLen + j] ^= cbcV[j];
                }

                /*
                 * swap the back up buffer into next position
                 */
                byte[] tmp;

                tmp = cbcV;
                cbcV = cbcNextV;
                cbcNextV = tmp;
                resultLen += BLOCK_SIZE;
            }
            inOff += blockSize;
        }

        return resultLen;
    }

}
