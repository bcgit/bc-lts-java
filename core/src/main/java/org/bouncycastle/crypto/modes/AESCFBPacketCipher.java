package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESNativeCFBPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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
        checkCFBParameter(parameters);
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        return len;
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
        byte[] cfbV = new byte[BLOCK_SIZE];
        byte[] iv, key;
        int[][] workingKey;
        byte[] s;
        int ROUNDS;
        int[] C = new int[4];
        try
        {
            if (parameters instanceof ParametersWithIV)
            {
                ParametersWithIV ivParam = (ParametersWithIV)parameters;
                // if null it's an IV changed only.
                if (ivParam.getParameters() != null)
                {
                    key = ((KeyParameter)ivParam.getParameters()).getKey();
                }
                else
                {
                    throw new IllegalArgumentException(ExceptionMessage.CFB_CIPHER_UNITIALIZED);
                }
                iv = ivParam.getIV().clone();
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
                throw new IllegalArgumentException(ExceptionMessage.CFB_CIPHER_UNITIALIZED);
            }
            int keyLen = key.length;
            checkKeyLength(keyLen);
            int KC = keyLen >>> 2;
            ROUNDS = KC + 6;
            workingKey = generateWorkingKey(key, KC, ROUNDS);
            s = Arrays.clone(S);
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        int inStart = inOff;
        int outStart = outOff;
        int blockCount = len >>> 4;
        boolean tail = (len & 15) != 0;
        int remaining=len;
        if (encryption)
        {

            for (int i = 0; i < blockCount; ++i)
            {
                encryptBlock(C, workingKey, s, ROUNDS);
                int4XorLittleEndian(C, input, inStart);
                int4ToLittleEndian(C, output, outStart);
                inStart += BLOCK_SIZE;
                outStart += BLOCK_SIZE;
                remaining -= BLOCK_SIZE;
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
                remaining -= BLOCK_SIZE;
            }
        }
        if (tail)
        {
            encryptBlock(C, workingKey, s, ROUNDS);
            Pack.intToLittleEndian(C, cfbV, 0);
            for (int i = 0; i < remaining ; ++i)
            {
                output[outStart + i] = (byte)(cfbV[i] ^ input[inStart + i]);
            }
        }
        Arrays.fill(cfbV, (byte)0);
        Arrays.fill(iv, (byte)0);
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
