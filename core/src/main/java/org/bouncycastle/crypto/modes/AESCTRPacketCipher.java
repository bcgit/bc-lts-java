package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESNativeCTRPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

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
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }
        checkParameters(parameters);
        return len;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, final int len,
                             byte[] output, int outOff)
            throws PacketCipherException
    {
        PacketCipherChecks.checkBoundsInputAndOutput(input, inOff, len, output, outOff);

        if (len == 0)
        {
            return 0;
        }

        byte[] ivOwned;
        byte[] counter = new byte[AESPacketCipher.BLOCK_SIZE];
        byte[] counterOut = new byte[AESPacketCipher.BLOCK_SIZE];
        int[][] workingKey;
        byte[] s = AESPacketCipher.createS(true);

        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) parameters;

            ivOwned = Arrays.clone(ivParam.getIV());
            if (ivOwned.length > AESPacketCipher.BLOCK_SIZE)
            {
                throw new IllegalArgumentException(ExceptionMessages.CTR16_IV_TOO_LONG);
            }

            if (ivOwned.length < 8)
            {
                throw new IllegalArgumentException(ExceptionMessages.CTR16_IV_TOO_SHORT);
            }
            System.arraycopy(ivOwned, 0, counter, 0, ivOwned.length);
            KeyParameter keyParameter = (KeyParameter) ivParam.getParameters();
            if (keyParameter == null)
            {
                throw PacketCipherException.from(new IllegalStateException(ExceptionMessages.CTR_CIPHER_UNITIALIZED));
            }
            int keyLen = keyParameter.getKey().length;
            PacketCipherChecks.checkKeyLength(keyLen);
            workingKey = AESPacketCipher.generateWorkingKey(true, keyParameter.getKey());

        }
        else
        {
            throw new IllegalArgumentException(ExceptionMessages.CTR_INVALID_PARAMETER);
        }


        int ctrSize = AESPacketCipher.BLOCK_SIZE - ivOwned.length;
        if (ctrSize > 0 && ctrSize < 4)
        {
            //
            // We may have a problem because they could pass in more info than
            // we have counter space for. With bigger counters they cannot pass in
            // an array big enough to overflow the counter.
            // If set with a 16byte iv then the assumption is the caller
            // knows what they are doing.
            //
            int ctrBits = ctrSize * 8;
            int maxBlocks = 1 << ctrBits;
            int maxLen = maxBlocks * AESPacketCipher.BLOCK_SIZE;
            if (len > maxLen)
            {
                throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
            }
        }

        int remaining = len;

        while (remaining > AESPacketCipher.BLOCK_SIZE)
        {

            AESPacketCipher.processBlock(true, workingKey, s, counter, 0, counterOut, 0);
            Bytes.xor(AESPacketCipher.BLOCK_SIZE, input, inOff, counterOut, 0, output, outOff);
            incrementCounter(counter, ivOwned);
            inOff += AESPacketCipher.BLOCK_SIZE;
            outOff += AESPacketCipher.BLOCK_SIZE;
            remaining -= AESPacketCipher.BLOCK_SIZE;
        }

        AESPacketCipher.processBlock(true, workingKey, s, counter, 0, counterOut, 0);
        Bytes.xor(remaining, input, inOff, counterOut, 0, output, outOff);


        return len;
    }


    private static void incrementCounter(byte[] counter, byte[] iv)
    {
        int i = counter.length;
        while (--i >= 0)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }


    @Override
    public String toString()
    {
        return "CTR-PS[Java](AES[Java])";
    }
}
