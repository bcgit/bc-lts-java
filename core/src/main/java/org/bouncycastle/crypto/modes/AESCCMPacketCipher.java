package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeCCMPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

public class AESCCMPacketCipher
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
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }
        int macSize = getMacSize(encryption, params);
        if (encryption)
        {
            return PacketCipherChecks.addCheckInputOverflow(len, macSize);
        }
        else if (len < macSize)
        {
            throw new OutputLengthException(ExceptionMessages.OUTPUT_LENGTH);
        }
        return len - macSize;
    }

    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] in, int inOff, int inLen,
                             byte[] output, int outOff)
    throws PacketCipherException
    {
        PacketCipherChecks.checkBoundsInput(in, inOff, inLen, output, outOff); // Output length varies for direction.
        byte[] nonce;
        byte[] initialAssociatedText;
        int macSize;
        KeyParameter keyParam;
        byte[] macBlock = new byte[AESPacketCipher.BLOCK_SIZE];
        byte[] counter = new byte[AESPacketCipher.BLOCK_SIZE];
        byte[] counterOut = new byte[16];
        byte[] block = null;
        if (!forEncryption)
        {
            block = new byte[AESPacketCipher.BLOCK_SIZE];
        }
        try
        {
            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters) params;
                macSize = getCCMMacSize(forEncryption, param.getMacSize());
                nonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();
                keyParam = param.getKey();
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV) params;
                macSize = 8;
                nonce = Arrays.clone(param.getIV());
                initialAssociatedText = null;
                keyParam = (KeyParameter) param.getParameters();
            }
            else
            {
                throw new IllegalArgumentException(ExceptionMessages.CCM_INVALID_PARAMETER);
            }
            PacketCipherChecks.checkInputAndOutputAEAD(forEncryption, in, inOff, inLen, output, outOff, macSize);
            // aeadLengthCheck(forEncryption, inLen, output, outOff, macSize);
            if (nonce == null || nonce.length < 7 || nonce.length > 13)
            {
                throw new IllegalArgumentException(ExceptionMessages.CCM_IV_SIZE);
            }

            PacketCipherChecks.checkKeyLength(keyParam.getKeyLength());

            // checkKeyLength(keyParam, ExceptionMessages.CCM_CIPHER_UNITIALIZED);
        }
        catch (IllegalArgumentException e)
        {
            throw PacketCipherException.from(e);
        }
        // This is not always true for the generalized Rijndael that allows larger block sizes
        int[][] workingKey = AESPacketCipher.generateWorkingKey(true, keyParam.getKey());
        byte[] s = AESPacketCipher.createS(true);
        int q = 15 - nonce.length; // OK because nonce len asserted to be [7,13]
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
            int inIndex = inOff;
            int outIndex = outOff;
            if (forEncryption)
            {
                outputLen = PacketCipherChecks.addCheckInputOverflow(inLen, macSize);
                calculateMac(in, inOff, inLen, macBlock, macSize, initialAssociatedText, nonce, workingKey, s);
                ctrProcessBlock(counter, counterOut, macBlock, 0, macBlock, 0, workingKey, s);

                // S0
                System.arraycopy(macBlock, 0, output, outOff + inLen, macSize);
                while (inIndex < (inOff + inLen - AESPacketCipher.BLOCK_SIZE))                 // S1...
                {
                    ctrProcessBlock(counter, counterOut, in, inIndex, output, outIndex, workingKey, s);
                    outIndex += AESPacketCipher.BLOCK_SIZE;
                    inIndex += AESPacketCipher.BLOCK_SIZE;
                }

                System.arraycopy(in, inIndex, macBlock, 0, inLen + inOff - inIndex);
                ctrProcessBlock(counter, counterOut, macBlock, 0, macBlock, 0, workingKey, s);
                System.arraycopy(macBlock, 0, output, outIndex, inLen + inOff - inIndex);
            }
            else
            {
                outputLen = inLen - macSize;
                System.arraycopy(in, inOff + outputLen, macBlock, 0, macSize);
                ctrProcessBlock(counter, counterOut, macBlock, 0, macBlock, 0, workingKey, s);
                Arrays.fill(macBlock, macSize, AESPacketCipher.BLOCK_SIZE, (byte) 0);
                while (inIndex < (inOff + outputLen - AESPacketCipher.BLOCK_SIZE))
                {
                    ctrProcessBlock(counter, counterOut, in, inIndex, output, outIndex, workingKey, s);
                    outIndex += AESPacketCipher.BLOCK_SIZE;
                    inIndex += AESPacketCipher.BLOCK_SIZE;
                }
                System.arraycopy(in, inIndex, block, 0, outputLen - (inIndex - inOff));
                ctrProcessBlock(counter, counterOut, block, 0, block, 0, workingKey, s);
                System.arraycopy(block, 0, output, outIndex, outputLen - (inIndex - inOff));
                calculateMac(output, outOff, outputLen, block, macSize, initialAssociatedText, nonce, workingKey, s);
                if (!Arrays.constantTimeAreEqual(macBlock, block))
                {
                    throw new InvalidCipherTextException("mac check in CCM failed");
                }
            }
        }
        catch (Exception ex)
        {
            exception = PacketCipherException.from(ex);
            throw exception;
        }
        finally
        {
            if (exception != null)
            {
                int l = Math.min(outputLen, output.length - outOff);
                Arrays.clear(output, outOff, l);
            }
        }

        Arrays.clear(workingKey);
        Arrays.clear(macBlock);
        Arrays.clear(counter);
        Arrays.clear(counterOut);
        Arrays.clear(block);
        Arrays.clear(s);
        return outputLen;
    }

    private static void calculateMac(byte[] in, int inOff, int inLen, byte[] macBlock, int macSize,
                                     byte[] aad, byte[] nonce, int[][] workingkey, byte[] s)
    {
        byte[] buf = new byte[AESPacketCipher.BLOCK_SIZE];
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

        AESPacketCipher.processBlock(true, workingkey, s, buf, 0, macBlock, 0);

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


            bufOff = cbcmacUpdate(buf, macBlock, bufOff, aad, 0, aad.length, workingkey, s);
            if (bufOff != 0)
            {
                Arrays.fill(buf, bufOff, AESPacketCipher.BLOCK_SIZE, (byte) 0);
                Bytes.xorTo(AESPacketCipher.BLOCK_SIZE, macBlock, 0, buf, 0);
                AESPacketCipher.processBlock(true, workingkey, s, buf, 0, macBlock, 0);
                bufOff = 0;
            }
        }

        if (inLen != 0)
        {
            bufOff = cbcmacUpdate(buf, macBlock, bufOff, in, inOff, inLen, workingkey, s);
            Arrays.fill(buf, bufOff, AESPacketCipher.BLOCK_SIZE, (byte) 0);
            Bytes.xorTo(AESPacketCipher.BLOCK_SIZE, buf, macBlock);
            AESPacketCipher.processBlock(true, workingkey, s, macBlock, 0, macBlock, 0);
        }

        Arrays.fill(macBlock, macSize, AESPacketCipher.BLOCK_SIZE, (byte) 0);
        Arrays.clear(buf);

    }


    private static int cbcmacUpdate(
            byte[] buf,
            byte[] accumulator,
            int bufOff,
            byte[] in,
            int inOff,
            int len,
            int[][] workingkey,
            byte[] s)
    {
        int gapLen = AESPacketCipher.BLOCK_SIZE - bufOff;
        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);
            Bytes.xorTo(AESPacketCipher.BLOCK_SIZE, buf, accumulator);
            AESPacketCipher.processBlock(true, workingkey, s, accumulator, 0, accumulator, 0);
            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;
            while (len > AESPacketCipher.BLOCK_SIZE)
            {
                Bytes.xor(AESPacketCipher.BLOCK_SIZE, accumulator, 0, in, inOff, accumulator, 0);
                AESPacketCipher.processBlock(true, workingkey, s, accumulator, 0, accumulator, 0);
                len -= AESPacketCipher.BLOCK_SIZE;
                inOff += AESPacketCipher.BLOCK_SIZE;
            }
        }
        System.arraycopy(in, inOff, buf, bufOff, len);
        bufOff += len;
        return bufOff;
    }


    protected static void ctrProcessBlock(byte[] counter, byte[] counterOut, byte[] in, int inOff,
                                          byte[] out, int outOff,
                                          int[][] workingkeys, byte[] s)
    {
        AESPacketCipher.processBlock(true, workingkeys, s, counter, 0, counterOut, 0);
        int i = counter.length;
        while (--i >= 0)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
        Bytes.xorTee(16, in, inOff, counterOut, 0, out, outOff);
    }


    @Override
    public String toString()
    {
        return "CCM-PS[Java](AES[Java])";
    }
}
