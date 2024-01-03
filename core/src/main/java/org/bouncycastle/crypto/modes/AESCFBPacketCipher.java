package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCFBPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;


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
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }

        if (parameters instanceof ParametersWithIV)
        {
            //
            // Test the IV as we have it.
            //
            if (((ParametersWithIV) parameters).getIV().length != AESPacketCipher.BLOCK_SIZE)
            {
                throw new IllegalArgumentException(ExceptionMessages.IV_LENGTH_16);
            }
            parameters = ((ParametersWithIV) parameters).getParameters();
        }

        if (parameters instanceof KeyParameter)
        {
            PacketCipherChecks.checkKeyLenIllegalArgumentException(
                    ((KeyParameter) parameters).getKeyLength());
        }

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
            return len;
        }

        // These are copies of parameter values.
        final byte[] keyOwned;
        final byte[] ivOwned;

        //
        // Deal with input parameters with IV
        //
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV) parameters;
            ivOwned = Arrays.clone(ivParam.getIV());

            if (ivOwned.length != AESPacketCipher.BLOCK_SIZE)
            {
                throw PacketCipherException.from(
                        new IllegalArgumentException(ExceptionMessages.IV_LENGTH_16));
            }

            parameters = ((ParametersWithIV) parameters).getParameters();
        }
        else
        {
            ivOwned = new byte[AESPacketCipher.BLOCK_SIZE];
        }

        // Deal with KeyParameter which may have been either passed in or
        // the parameter within the ParameterWithIV
        if (parameters instanceof KeyParameter)
        {
            KeyParameter kp = (KeyParameter) parameters;
            PacketCipherChecks.checkKeyLength(kp.getKeyLength());
            keyOwned = Arrays.clone(kp.getKey());
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INVALID_PARAM_TYPE));
        }

        // Create AES parameters
        final byte[] s = AESPacketCipher.createS(true);
        final int[][] workingKey = AESPacketCipher.generateWorkingKey(true, keyOwned);


        byte[] keyBlock = new byte[AESPacketCipher.BLOCK_SIZE];
        AESPacketCipher.processBlock(true, workingKey, s, ivOwned, 0, keyBlock, 0);
        int remaining = len;

        if (encryption)
        {
            while (remaining > AESPacketCipher.BLOCK_SIZE)
            {
                Bytes.xor(AESPacketCipher.BLOCK_SIZE, input, inOff, keyBlock, 0, output, outOff);
                AESPacketCipher.processBlock(true, workingKey, s, output, outOff, keyBlock, 0);
                remaining -= AESPacketCipher.BLOCK_SIZE;
                inOff += AESPacketCipher.BLOCK_SIZE;
                outOff += AESPacketCipher.BLOCK_SIZE;
            }
        }
        else
        {
            // Input and output may overlap.
            byte[] lastCipherText = new byte[16];
            while (remaining > AESPacketCipher.BLOCK_SIZE)
            {
                System.arraycopy(input, inOff, lastCipherText, 0, lastCipherText.length);
                Bytes.xor(AESPacketCipher.BLOCK_SIZE, input, inOff, keyBlock, 0, output, outOff);
                AESPacketCipher.processBlock(true, workingKey, s, lastCipherText, 0, keyBlock, 0);
                remaining -= AESPacketCipher.BLOCK_SIZE;
                inOff += AESPacketCipher.BLOCK_SIZE;
                outOff += AESPacketCipher.BLOCK_SIZE;
            }
        }
        Bytes.xor(remaining, input, inOff, keyBlock, 0, output, outOff);

        return len;
    }

    @Override
    public String toString()
    {
        return "CFB-PS[Java](AES[Java])";
    }
}
