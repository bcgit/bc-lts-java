package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESCCMPacketCipher
    extends PacketCipherEngine
{

    public static AESCCMPacketCipher newInstance()
    {
        return new AESCCMPacketCipher();
    }

    private AESCCMPacketCipher()
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
            AEADParameters param = (AEADParameters)params;
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
        return len - macSize;
    }

    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] in, int inOff, int inLen, byte[] output, int outOff)
        throws PacketCipherException
    {
        processPacketExceptionCheck(in, inOff, inLen, output, outOff);
        byte[] nonce;
        byte[] initialAssociatedText;
        int macSize;
        KeyParameter keyParam;
        byte[] macBlock;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;
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
            ParametersWithIV param = (ParametersWithIV)params;
            macSize = getMacSize(forEncryption, 64);
            nonce = param.getIV();
            initialAssociatedText = null;
            keyParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CCM"));
        }
        if (forEncryption)
        {
            if (output.length - outOff < inLen + macSize)
            {
                throw PacketCipherException.from(new OutputLengthException(ExceptionMessage.OUTPUT_LENGTH));
            }
        }
        else
        {
            if (output.length - outOff < inLen - macSize)
            {
                throw PacketCipherException.from(new OutputLengthException(ExceptionMessage.OUTPUT_LENGTH));
            }
            if (in.length - inOff < macSize)
            {
                throw PacketCipherException.from(new DataLengthException(ExceptionMessage.INPUT_SHORT));
            }
        }
        if (nonce == null || nonce.length < 7 || nonce.length > 13)
        {
            throw PacketCipherException.from(new IllegalArgumentException("nonce must have length from 7 to 13 octets"));
        }
        if (keyParam == null)
        {
            throw PacketCipherException.from(new IllegalStateException("CCM cipher unitialized."));
        }

        int keyLen = keyParam.getKey().length;
        if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.AES_KEY_LENGTH));
        }
        int KC = keyLen >>> 2;
        int ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
        int[][] workingKey = generateWorkingKey(keyParam.getKey(), KC, ROUNDS);
        byte[] s = Arrays.clone(S);
        int[] counterIn = new int[4];
        int[] counterOut = new int[4];
        int n = nonce.length;
        int q = 15 - n;
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
            byte[] counter = new byte[BLOCK_SIZE];
            counter[0] = (byte)((q - 1) & 0x7);
            System.arraycopy(nonce, 0, counter, 1, nonce.length);
            littleEndianToInt4(counter, 0, counterIn);
            //byte[] counterOut = new byte[BLOCK_SIZE];
            int inIndex = inOff;
            int outIndex = outOff;
            macBlock = new byte[BLOCK_SIZE];
            if (forEncryption)
            {
                outputLen = inLen + macSize;
                calculateMac(in, inOff, inLen, macBlock, macSize, initialAssociatedText, nonce, workingKey, s, ROUNDS);
                byte[] encMac = new byte[BLOCK_SIZE];
                ctrProcessBlock(counter, counterIn, counterOut, macBlock, 0, encMac, 0, workingKey, s, ROUNDS);   // S0
                while (inIndex < (inOff + inLen - BLOCK_SIZE))                 // S1...
                {
                    ctrProcessBlock(counter, counterIn, counterOut, in, inIndex, output, outIndex, workingKey, s, ROUNDS);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }
                byte[] block = new byte[BLOCK_SIZE];
                System.arraycopy(in, inIndex, block, 0, inLen + inOff - inIndex);
                ctrProcessBlock(counter, counterIn, counterOut, block, 0, block, 0, workingKey, s, ROUNDS);
                System.arraycopy(block, 0, output, outIndex, inLen + inOff - inIndex);
                System.arraycopy(encMac, 0, output, outOff + inLen, macSize);
            }
            else
            {
                outputLen = inLen - macSize;
                System.arraycopy(in, inOff + outputLen, macBlock, 0, macSize);
                ctrProcessBlock(counter, counterIn, counterOut, macBlock, 0, macBlock, 0, workingKey, s, ROUNDS);
                Arrays.fill(macBlock, macSize, macBlock.length, (byte)0);
                while (inIndex < (inOff + outputLen - BLOCK_SIZE))
                {
                    ctrProcessBlock(counter, counterIn, counterOut, in, inIndex, output, outIndex, workingKey, s, ROUNDS);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }
                byte[] block = new byte[BLOCK_SIZE];
                System.arraycopy(in, inIndex, block, 0, outputLen - (inIndex - inOff));
                ctrProcessBlock(counter, counterIn, counterOut,block, 0, block, 0, workingKey, s, ROUNDS);
                System.arraycopy(block, 0, output, outIndex, outputLen - (inIndex - inOff));
                byte[] calculatedMacBlock = new byte[BLOCK_SIZE];
                calculateMac(output, outOff, outputLen, calculatedMacBlock, macSize, initialAssociatedText, nonce, workingKey, s, ROUNDS);
                if (!Arrays.constantTimeAreEqual(macBlock, calculatedMacBlock))
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
        if (exception != null)
        {
            Arrays.fill(output, (byte)0);
            throw exception;
        }
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
            buf[buf.length - count++] = (byte)(q & 0xff);
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
                buf[0] = (byte)(textLength >> 8);
                buf[1] = (byte)textLength;
                bufOff = 2;
            }
            else // can't go any higher than 2^32
            {
                buf[0] = (byte)0xff;
                buf[1] = (byte)0xfe;
                buf[2] = (byte)(textLength >> 24);
                buf[3] = (byte)(textLength >> 16);
                buf[4] = (byte)(textLength >> 8);
                buf[5] = (byte)textLength;
                bufOff = 6;
            }
            bufOff = cbcmacUpdate(buf, C, bufOff, aad, 0, aad.length, workingkey, s, ROUNDS);
            if (bufOff != 0)
            {
                Arrays.fill(buf, bufOff, BLOCK_SIZE, (byte)0);
                int4XorLittleEndian(C, buf, 0);
                encryptBlock(C, workingkey, s, ROUNDS);
                bufOff = 0;
            }
        }
        if (inLen != 0)
        {
            bufOff = cbcmacUpdate(buf, C, bufOff, in, inOff, inLen, workingkey, s, ROUNDS);
            Arrays.fill(buf, bufOff, BLOCK_SIZE, (byte)0);
            int4XorLittleEndian(C, buf, 0);
            encryptBlock(C, workingkey, s, ROUNDS);
        }
        int4ToLittleEndian(C, macBlock, 0);
        Arrays.fill(macBlock, macSize, BLOCK_SIZE, (byte)0);
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

    private void ctrProcessBlock(byte[] counter, int[] counterIn, int[] counterOut, byte[] in, int inOff, byte[] out, int outOff,
                                 int[][] workingkeys, byte[] s, int ROUNDS)
    {
        encryptBlock(counterIn, counterOut, workingkeys, s, ROUNDS);
        int i;
        int4XorLittleEndian(counterOut, in , inOff);
        int4ToLittleEndian(counterOut, out, outOff);
        i = counter.length;
        while (--i >= 0)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
        if (i >= 12)
        {
            counterIn[3] = Pack.littleEndianToInt(counter, 12);
        }
        else if (i >= 8)
        {
            counterIn[2] = Pack.littleEndianToInt(counter, 8);
            counterIn[3] = Pack.littleEndianToInt(counter, 12);
        }
        else if (i >= 4)
        {
            counterIn[1] = Pack.littleEndianToInt(counter, 4);
            counterIn[2] = Pack.littleEndianToInt(counter, 8);
            counterIn[3] = Pack.littleEndianToInt(counter, 12);
        }
        else
        {
            counterIn[0] = Pack.littleEndianToInt(counter, 0);
            counterIn[1] = Pack.littleEndianToInt(counter, 4);
            counterIn[2] = Pack.littleEndianToInt(counter, 8);
            counterIn[3] = Pack.littleEndianToInt(counter, 12);
        }
    }

    private int cbcmacUpdate(byte[] buf, int[] C, int bufOff, byte[] in, int inOff, int len, int[][] workingkey, byte[] s, int ROUNDS)
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
        return "CCM Packet Cipher";
    }
}
