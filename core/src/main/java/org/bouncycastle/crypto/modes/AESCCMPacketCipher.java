package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESCCMPacketCipher
    implements PacketCipher
{
    private static final int BLOCK_SIZE = 16;

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
        if (in == null)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.INPUT_NULL));
        }
        if (inOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }
        if (outOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }
        if (inLen < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE));
        }
        BlockCipher cipher = new AESEngine();
        CipherParameters cipherParameters;
        byte[] nonce;
        byte[] initialAssociatedText;
        int macSize;
        CipherParameters keyParam = null;
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


            cipherParameters = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;
            macSize = getMacSize(forEncryption, 64);
            nonce = param.getIV();
            initialAssociatedText = null;
            cipherParameters = param.getParameters();
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException("invalid parameters passed to CCM: "));
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
        // NOTE: Very basic support for key re-use, but no performance gain from it
        if (cipherParameters != null)
        {
            keyParam = cipherParameters;
        }

        if (nonce == null || nonce.length < 7 || nonce.length > 13)
        {
            throw PacketCipherException.from(new IllegalArgumentException("nonce must have length from 7 to 13 octets"));
        }

        if (keyParam == null)
        {
            throw PacketCipherException.from(new IllegalStateException("CCM cipher unitialized."));
        }

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
            byte[] iv = new byte[BLOCK_SIZE];
            iv[0] = (byte)((q - 1) & 0x7);
            System.arraycopy(nonce, 0, iv, 1, nonce.length);

            BlockCipher ctrCipher = new SICBlockCipher(cipher);
            ctrCipher.init(forEncryption, new ParametersWithIV(keyParam, iv));

            int inIndex = inOff;
            int outIndex = outOff;
            macBlock = new byte[BLOCK_SIZE];
            if (forEncryption)
            {
                outputLen = inLen + macSize;


                calculateMac(in, inOff, inLen, macBlock, cipher, macSize, keyParam, initialAssociatedText, nonce);

                byte[] encMac = new byte[BLOCK_SIZE];

                ctrCipher.processBlock(macBlock, 0, encMac, 0);   // S0

                while (inIndex < (inOff + inLen - BLOCK_SIZE))                 // S1...
                {
                    ctrCipher.processBlock(in, inIndex, output, outIndex);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }

                byte[] block = new byte[BLOCK_SIZE];

                System.arraycopy(in, inIndex, block, 0, inLen + inOff - inIndex);

                ctrCipher.processBlock(block, 0, block, 0);

                System.arraycopy(block, 0, output, outIndex, inLen + inOff - inIndex);

                System.arraycopy(encMac, 0, output, outOff + inLen, macSize);
            }
            else
            {
                outputLen = inLen - macSize;
                System.arraycopy(in, inOff + outputLen, macBlock, 0, macSize);
                ctrCipher.processBlock(macBlock, 0, macBlock, 0);
                for (int i = macSize; i != macBlock.length; i++)
                {
                    macBlock[i] = 0;
                }

                while (inIndex < (inOff + outputLen - BLOCK_SIZE))
                {
                    ctrCipher.processBlock(in, inIndex, output, outIndex);
                    outIndex += BLOCK_SIZE;
                    inIndex += BLOCK_SIZE;
                }

                byte[] block = new byte[BLOCK_SIZE];

                System.arraycopy(in, inIndex, block, 0, outputLen - (inIndex - inOff));

                ctrCipher.processBlock(block, 0, block, 0);

                System.arraycopy(block, 0, output, outIndex, outputLen - (inIndex - inOff));

                byte[] calculatedMacBlock = new byte[BLOCK_SIZE];

                calculateMac(output, outOff, outputLen, calculatedMacBlock, cipher, macSize, keyParam, initialAssociatedText, nonce);

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


        if (exception != null)
        {
            throw exception;
        }
        return outputLen;
    }

    private int calculateMac(byte[] data, int dataOff, int dataLen, byte[] macBlock, BlockCipher cipher, int macSize,
                             CipherParameters keyParam, byte[] initialAssociatedText, byte[] nonce)
    {
        Mac cMac = new CBCBlockCipherMac(cipher, macSize * 8);

        cMac.init(keyParam);

        //
        // build b0
        //
        byte[] b0 = new byte[16];

        if (initialAssociatedText.length > 0)
        {
            b0[0] |= 0x40;
        }

        b0[0] |= (((cMac.getMacSize() - 2) / 2) & 0x7) << 3;

        b0[0] |= ((15 - nonce.length) - 1) & 0x7;

        System.arraycopy(nonce, 0, b0, 1, nonce.length);

        int q = dataLen;
        int count = 1;
        while (q > 0)
        {
            b0[b0.length - count] = (byte)(q & 0xff);
            q >>>= 8;
            count++;
        }

        cMac.update(b0, 0, b0.length);

        //
        // process associated text
        //
        if (initialAssociatedText.length > 0)
        {
            int extra;

            int textLength = initialAssociatedText.length;
            if (textLength < ((1 << 16) - (1 << 8)))
            {
                cMac.update((byte)(textLength >> 8));
                cMac.update((byte)textLength);

                extra = 2;
            }
            else // can't go any higher than 2^32
            {
                cMac.update((byte)0xff);
                cMac.update((byte)0xfe);
                cMac.update((byte)(textLength >> 24));
                cMac.update((byte)(textLength >> 16));
                cMac.update((byte)(textLength >> 8));
                cMac.update((byte)textLength);

                extra = 6;
            }

            if (initialAssociatedText != null)
            {
                cMac.update(initialAssociatedText, 0, initialAssociatedText.length);
            }

            extra = (extra + textLength) % 16;
            if (extra != 0)
            {
                for (int i = extra; i != 16; i++)
                {
                    cMac.update((byte)0x00);
                }
            }
        }

        //
        // add the text
        //
        cMac.update(data, dataOff, dataLen);

        return cMac.doFinal(macBlock, 0);
    }

    private int getMacSize(boolean forEncryption, int requestedMacBits)
    {
        if (forEncryption && (requestedMacBits < 32 || requestedMacBits > 128 || 0 != (requestedMacBits & 15)))
        {
            throw new IllegalArgumentException("tag length in octets must be one of {4,6,8,10,12,14,16}");
        }

        return requestedMacBits >>> 3;
    }
}
