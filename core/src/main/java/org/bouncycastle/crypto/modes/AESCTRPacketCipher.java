package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESNativeCTRPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCTRPacketCipher
    extends AESPacketCipherEngine
    implements AESCTRModePacketCipher
{
    public static AESCTRModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CTR_PC))
        {
            return new AESNativeCTRPacketCipher();
        }

        return new AESCTRPacketCipher();
    }

    private AESCTRPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        checkParameters(parameters);
        return len;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
        processPacketExceptionCheck(input, inOff, len, output, outOff);
        if (output.length - outOff < len)
        {
            throw PacketCipherException.from(new OutputLengthException(ExceptionMessage.OUTPUT_LENGTH));
        }
        byte[] IV;
        byte[] counter = new byte[BLOCK_SIZE];
        int[] counterIn = new int[4];
        int[] counterOut = new int[4];
        int ROUNDS;
        int[][] workingKey;
        byte[] s = Arrays.clone(S);
        try
        {
            if (parameters instanceof ParametersWithIV)
            {
                ParametersWithIV ivParam = (ParametersWithIV)parameters;
                IV = Arrays.clone(ivParam.getIV());
                if (BLOCK_SIZE < IV.length)
                {
                    throw new IllegalArgumentException(ExceptionMessage.CTR16_IV_TOO_LONG);
                }
                //int maxCounterSize = Math.min(8, BLOCK_SIZE >> 1);
                if (BLOCK_SIZE - IV.length > 8) // 8 is the maxCounterSize
                {
                    throw new IllegalArgumentException(ExceptionMessage.CTR16_IV_TOO_SHORT);
                }
                System.arraycopy(IV, 0, counter, 0, IV.length);
                KeyParameter keyParameter = (KeyParameter)ivParam.getParameters();
                if (keyParameter == null)
                {
                    throw PacketCipherException.from(new IllegalStateException(ExceptionMessage.CTR_CIPHER_UNITIALIZED));
                }
                int keyLen = keyParameter.getKey().length;
                checkKeyLength(keyLen);
                int KC = keyLen >>> 2;
                ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
                workingKey = generateWorkingKey(keyParameter.getKey(), KC, ROUNDS);
            }
            else
            {
                throw new IllegalArgumentException(ExceptionMessage.CTR_INVALID_PARAMETER);
            }
        }
        catch (Exception e)
        {
            throw PacketCipherException.from(e);
        }
        littleEndianToInt4(counter, 0, counterIn);
        int blockCount = len >>> 4;
        int inIndex = inOff;
        int outIndex = outOff;
        for (int k = 0; k < blockCount; ++k)
        {
            ctrProcessBlock(counter, counterIn, counterOut, input, inIndex, output, outIndex, workingKey, s, ROUNDS);
            inIndex += BLOCK_SIZE;
            outIndex += BLOCK_SIZE;
        }
        encryptBlock(counterIn, counterOut, workingKey, s, ROUNDS);
        int4ToLittleEndian(counterOut, counter, 0);
        for (int i = 0; i < len + inOff - inIndex; ++i)
        {
            output[outIndex + i] = (byte)(counter[i] ^ input[inIndex + i]);
        }
        return len;
    }

    @Override
    public String toString()
    {
        return "CTR-PS[Java](AES[Java])";
    }
}
