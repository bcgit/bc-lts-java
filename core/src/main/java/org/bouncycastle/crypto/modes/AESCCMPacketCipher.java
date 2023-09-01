package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCCMPacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCCMPacketCipher
        extends AESPacketCipherEngine
        implements AESCCMModePacketCipher
{
    public static AESCCMModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CCM_PC))
        {
            return new AESNativeCCMPacketCipher();
        }
        return new AESCCMPacketCipher();
    }

    public AESCCMPacketCipher()
    {
    }

    @Override
    public int getOutputSize(boolean encryption, CipherParameters params, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        int macSize;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) params;
            macSize = getMacSize(encryption, param.getMacSize());
        }
        else if (params instanceof ParametersWithIV)
        {
            macSize = 8;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to CCM: " + params.getClass().getName());
        }
        if (encryption)
        {
            return len + macSize;
        }
        else if (len < macSize)
        {
            throw new DataLengthException(ExceptionMessage.OUTPUT_LENGTH);
        }
        return len - macSize;
    }

    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] in, int inOff, int inLen,
                             byte[] output, int outOff)
            throws PacketCipherException
    {
        processPacketExceptionCheck(in, inOff, inLen, output, outOff);
        byte[] nonce;
        byte[] initialAssociatedText;
        int macSize;
        KeyParameter keyParam;
        byte[] macBlock = new byte[BLOCK_SIZE];
        byte[] counter = new byte[BLOCK_SIZE];
        int[] counterIn = new int[4];
        int[] counterOut = new int[4];
        byte[] block = null;
        if (!forEncryption)
        {
            block = new byte[BLOCK_SIZE];
        }
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters) params;
            try
            {
                macSize = getMacSize(forEncryption, param.getMacSize());
            }
            catch (IllegalArgumentException e)
            {
                throw PacketCipherException.from(e);
            }
            nonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV) params;
            macSize = 8;
            nonce = param.getIV().clone();
            initialAssociatedText = null;
            keyParam = (KeyParameter) param.getParameters();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CCM"));
        }
        AEADLengthCheck(forEncryption, inLen, output, outOff, macSize);
        if (nonce == null || nonce.length < 7 || nonce.length > 13)
        {
            throw PacketCipherException.from(new IllegalArgumentException("nonce must have length from 7 to 13 " +
                    "octets"));
        }
        if (keyParam == null)
        {
            throw PacketCipherException.from(new IllegalStateException("CCM cipher unitialized."));
        }
        int keyLen = keyParam.getKey().length;
        checkKeyLength(keyLen);
        int KC = keyLen >>> 2;
        int ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
        int[][] workingKey = generateWorkingKey(keyParam.getKey(), KC, ROUNDS);
        byte[] s = Arrays.clone(S);
        int q = 15 - nonce.length;
        if (q < 4)
        {
            int limitLen = 1 << (q << 3);
            if (inLen >= limitLen)
            {
                throw PacketCipherException.from(new IllegalStateException("CCM packet too large for choice of q."));
            }
        }
        PacketCipherException exception = null;
        int outputLen = 0;
        try
        {
            counter[0] = (byte) ((q - 1) & 0x7);
            System.arraycopy(nonce, 0, counter, 1, nonce.length);
            littleEndianToInt4(counter, 0, counterIn);
            int inIndex = inOff;
            int outIndex = outOff;
            if (forEncryption)
            {
                outputLen = inLen + macSize;
                calculateMac(in, inOff, inLen, macBlock, macSize, initialAssociatedText, nonce, workingKey, s, ROUNDS);
                ctrProcessBlock(counter, counterIn, counterOut, macBlock, 0, macBlock, 0, workingKey, s, ROUNDS);
                // S0
                System.arraycopy(macBlock, 0, output, outOff + inLen, macSize);
                while (inIndex < (inOff + inLen - BLOCK_SIZE))                 // S1...
                {
                    ctrProcessBlock(counter, counterIn, counterOut, in, inIndex, output, outIndex, workingKey, s,
                            ROUNDS);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }
                System.arraycopy(in, inIndex, macBlock, 0, inLen + inOff - inIndex);
                ctrProcessBlock(counter, counterIn, counterOut, macBlock, 0, macBlock, 0, workingKey, s, ROUNDS);
                System.arraycopy(macBlock, 0, output, outIndex, inLen + inOff - inIndex);
            }
            else
            {
                outputLen = inLen - macSize;
                System.arraycopy(in, inOff + outputLen, macBlock, 0, macSize);
                ctrProcessBlock(counter, counterIn, counterOut, macBlock, 0, macBlock, 0, workingKey, s, ROUNDS);
                Arrays.fill(macBlock, macSize, BLOCK_SIZE, (byte) 0);
                while (inIndex < (inOff + outputLen - BLOCK_SIZE))
                {
                    ctrProcessBlock(counter, counterIn, counterOut, in, inIndex, output, outIndex, workingKey, s,
                            ROUNDS);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }
                System.arraycopy(in, inIndex, block, 0, outputLen - (inIndex - inOff));
                ctrProcessBlock(counter, counterIn, counterOut, block, 0, block, 0, workingKey, s, ROUNDS);
                System.arraycopy(block, 0, output, outIndex, outputLen - (inIndex - inOff));
                calculateMac(output, outOff, outputLen, block, macSize, initialAssociatedText, nonce, workingKey, s,
                        ROUNDS);
                if (!Arrays.constantTimeAreEqual(macBlock, block))
                {
                    throw new InvalidCipherTextException("mac check in CCM failed");
                }
            }
        }
        catch (Exception ex)
        {
            exception = PacketCipherException.from(ex);
        }
        for (int[] ints : workingKey)
        {
            Arrays.fill(ints, 0);
        }
        AEADExceptionHandler(output, outOff, exception, outputLen);
        return outputLen;
    }

    private void calculateMac(byte[] in, int inOff, int inLen, byte[] macBlock, int macSize,
                              byte[] aad, byte[] nonce, int[][] workingkey, byte[] s, int ROUNDS)
    {
        byte[] buf = new byte[BLOCK_SIZE];
        int[] C = new int[4];
        int bufOff = 0;
        if (aad != null && aad.length > 0)
        {
            buf[0] |= 0x40;
        }
        buf[0] |= ((((macSize - 2) >> 1) & 0x7) << 3) | (((15 - nonce.length) - 1) & 0x7);
        System.arraycopy(nonce, 0, buf, 1, nonce.length);
        int q = inLen;
        int count = 1;
        while (q > 0)
        {
            buf[buf.length - count++] = (byte) (q & 0xff);
            q >>>= 8;
        }
        littleEndianToInt4(buf, 0, C);
        encryptBlock(C, workingkey, s, ROUNDS);
        //
        // process associated text
        //
        if (aad != null && aad.length > 0)
        {
            int textLength = aad.length;
            if (textLength < ((1 << 16) - (1 << 8)))
            {
                buf[0] = (byte) (textLength >> 8);
                buf[1] = (byte) textLength;
                bufOff = 2;
            }
            else // can't go any higher than 2^32
            {
                buf[0] = (byte) 0xff;
                buf[1] = (byte) 0xfe;
                buf[2] = (byte) (textLength >> 24);
                buf[3] = (byte) (textLength >> 16);
                buf[4] = (byte) (textLength >> 8);
                buf[5] = (byte) textLength;
                bufOff = 6;
            }
            bufOff = cbcmacUpdate(buf, C, bufOff, aad, 0, aad.length, workingkey, s, ROUNDS);
            if (bufOff != 0)
            {
                Arrays.fill(buf, bufOff, BLOCK_SIZE, (byte) 0);
                int4XorLittleEndian(C, buf, 0);
                encryptBlock(C, workingkey, s, ROUNDS);
                bufOff = 0;
            }
        }
        if (inLen != 0)
        {
            bufOff = cbcmacUpdate(buf, C, bufOff, in, inOff, inLen, workingkey, s, ROUNDS);
            Arrays.fill(buf, bufOff, BLOCK_SIZE, (byte) 0);
            int4XorLittleEndian(C, buf, 0);
            encryptBlock(C, workingkey, s, ROUNDS);
        }
        int4ToLittleEndian(C, macBlock, 0);
        Arrays.fill(macBlock, macSize, BLOCK_SIZE, (byte) 0);
        Arrays.fill(C, 0);
    }

    private int getMacSize(boolean forEncryption, int requestedMacBits)
    {
        if (forEncryption && (requestedMacBits < 32 || requestedMacBits > 128 || 0 != (requestedMacBits & 15)))
        {
            throw new IllegalArgumentException("tag length in octets must be one of {4,6,8,10,12,14,16}");
        }
        return requestedMacBits >>> 3;
    }

    private int cbcmacUpdate(byte[] buf, int[] C, int bufOff, byte[] in, int inOff, int len, int[][] workingkey,
                             byte[] s, int ROUNDS)
    {
        int gapLen = BLOCK_SIZE - bufOff;
        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);
            int4XorLittleEndian(C, buf, 0);
            encryptBlock(C, workingkey, s, ROUNDS);
            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;
            while (len > BLOCK_SIZE)
            {
                int4XorLittleEndian(C, in, inOff);
                encryptBlock(C, workingkey, s, ROUNDS);
                len -= BLOCK_SIZE;
                inOff += BLOCK_SIZE;
            }
        }
        System.arraycopy(in, inOff, buf, bufOff, len);
        bufOff += len;
        return bufOff;
    }

    @Override
    public String toString()
    {
        return "CCM Packet Cipher (Java)";
    }
}
