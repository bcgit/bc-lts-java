package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCBCPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

public class AESCBCPacketCipher
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
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }
        if (len % AESPacketCipher.BLOCK_SIZE != 0)
        {
            throw new IllegalArgumentException(ExceptionMessages.BLOCK_CIPHER_16_INPUT_LENGTH_INVALID);
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
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
    throws PacketCipherException
    {
        PacketCipherChecks.checkBoundsInputAndOutputWithBlockSize_16(input, inOff, len, output, outOff);

        if (len == 0)
        {
            return len;
        }

        int blockCount = len / AESPacketCipher.BLOCK_SIZE;

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

        final byte[] s = AESPacketCipher.createS(encryption);
        final int[][] workingKey = AESPacketCipher.generateWorkingKey(encryption, keyOwned);

        // Mode values
        byte[] cbcV = Arrays.clone(ivOwned);
        byte[] cbcNextV = new byte[AESPacketCipher.BLOCK_SIZE];


        // Process blocks
        for (int i = 0; i < blockCount; i++)
        {
            if (encryption)
            {
                Bytes.xorTo(AESPacketCipher.BLOCK_SIZE, input, inOff, cbcV, 0);
                AESPacketCipher.processBlock(encryption, workingKey, s, cbcV, 0, output, outOff);
                System.arraycopy(output, outOff, cbcV, 0, cbcV.length);
            }
            else
            {
                System.arraycopy(input, inOff, cbcNextV, 0, AESPacketCipher.BLOCK_SIZE);
                AESPacketCipher.processBlock(encryption, workingKey, s, input, inOff, output, outOff);
                Bytes.xorTo(AESPacketCipher.BLOCK_SIZE, cbcV, 0, output, outOff);
                byte[] tmp;
                tmp = cbcV;
                cbcV = cbcNextV;
                cbcNextV = tmp;
            }
            outOff += AESPacketCipher.BLOCK_SIZE;
            inOff += AESPacketCipher.BLOCK_SIZE;
        }

        Arrays.clear(keyOwned);
        Arrays.clear(ivOwned);
        Arrays.clear(cbcNextV);
        Arrays.fill(cbcV, (byte) 0);
        Arrays.clear(workingKey);
        Arrays.clear(s);

        return blockCount * AESPacketCipher.BLOCK_SIZE;

    }

    @Override
    public String toString()
    {
        return "CBC-PS[Java](AES[Java])";
    }
}
