package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.BasicGCMExponentiator;
import org.bouncycastle.crypto.modes.gcm.GCMExponentiator;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESGCMPacketCipher
    implements PacketCipher
{
    private static final int BLOCK_SIZE = 16;

    // not final due to a compiler bug
    private BlockCipher cipher;
    private GCMMultiplier multiplier;
    private GCMExponentiator exp;

    // These fields are set by init and not modified by processing
    private boolean forEncryption;

    private int macSize;
    private byte[] nonce;
    private byte[] H;
    private byte[] J0;

    // These fields are modified during processing
    private byte[] bufBlock;
    private byte[] macBlock;
    private byte[] S, S_at, S_atPre;
    private byte[] counter;
    private int blocksRemaining;
    private int bufOff;
    private long totalLength;
    private byte[] atBlock;
    private int atBlockPos;
    private long atLength;
    private long atLengthPre;

    public static AESGCMPacketCipher newInstance()
    {
        return new AESGCMPacketCipher();
    }

    private AESGCMPacketCipher()
    {

    }

    @Override
    public int getOutputSize(boolean forEncryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE);
        }
        int macSize;
        if (parameters instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)parameters;
            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            macSize = macSizeBits / 8;

        }
        else if (parameters instanceof ParametersWithIV)
        {
            macSize = 16;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }
        if (forEncryption)
        {
            return len + macSize;
        }
        return len < macSize ? 0 : len - macSize;
    }


    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
       /*
            First round of work:
            - Use java GCM, create new instance of GCM, initialise it, then update and doFinal.

            Important:
                If at any stage there is an exception thrown it must zero any data it has written out to output

        */
        if (input == null)
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
        if (len < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessage.LEN_NEGATIVE));
        }
        Throwable exceptionThrown = null;
        try
        {
            this.forEncryption = forEncryption;
            this.macBlock = null;

            KeyParameter keyParam;
            byte[] newNonce;

            byte[] initialAssociatedText;
            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters)params;

                newNonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();

                int macSizeBits = param.getMacSize();
                if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
                {
                    throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
                }

                macSize = macSizeBits / 8;
                keyParam = param.getKey();
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV)params;

                newNonce = param.getIV();
                initialAssociatedText = null;
                macSize = 16;
                keyParam = (KeyParameter)param.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("invalid parameters passed to GCM");
            }
            if (forEncryption)
            {
                if (output.length - outOff < len + macSize)
                {
                    throw new OutputLengthException(ExceptionMessage.OUTPUT_LENGTH);
                }
            }
            else
            {
                if (output.length - outOff < len - macSize)
                {
                    throw new OutputLengthException(ExceptionMessage.OUTPUT_LENGTH);
                }
                if (input.length - inOff < macSize)
                {
                    throw new DataLengthException(ExceptionMessage.INPUT_SHORT);
                }
            }
            int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize);
            this.bufBlock = new byte[bufLength];

            if (newNonce == null || newNonce.length < 12)
            {
                throw new IllegalArgumentException("IV must be at least 12 byte");
            }

            nonce = newNonce;
            if (keyParam != null)
            {
                byte[] lastKey = keyParam.getKey();
            }

            // TODO Restrict macSize to 16 if nonce length not 12?

            // Cipher always used in forward mode
            // if keyParam is null we're reusing the last key.
            if (keyParam != null)
            {
                cipher = new AESEngine();
                multiplier = new Tables4kGCMMultiplier();
                cipher.init(true, keyParam);

                this.H = new byte[BLOCK_SIZE];
                cipher.processBlock(H, 0, H, 0);

                // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
                multiplier.init(H);
                exp = null;
            }
            else if (this.H == null)
            {
                throw new IllegalArgumentException("Key must be specified in initial init");
            }

            this.J0 = new byte[BLOCK_SIZE];

            if (nonce.length == 12)
            {
                System.arraycopy(nonce, 0, J0, 0, nonce.length);
                this.J0[BLOCK_SIZE - 1] = 0x01;
            }
            else
            {
                //gHASH
                for (int pos = 0; pos < nonce.length; pos += BLOCK_SIZE)
                {
                    int num = Math.min(nonce.length - pos, BLOCK_SIZE);
                    gHASHPartial(J0, nonce, pos, num);
                }

                byte[] X = new byte[BLOCK_SIZE];
                Pack.longToBigEndian((long)nonce.length * 8, X, 8);
                gHASHBlock(J0, X);
            }

            S = new byte[BLOCK_SIZE];
            S_at = new byte[BLOCK_SIZE];
            S_atPre = new byte[BLOCK_SIZE];
            atBlock = new byte[BLOCK_SIZE];
            atBlockPos = 0;
            atLength = 0;
            atLengthPre = 0;
            counter = Arrays.clone(J0);
            blocksRemaining = -2;      // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
            bufOff = 0;
            totalLength = 0;

            if (initialAssociatedText != null)
            {
                processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
            }
        }
        catch (Throwable ex)
        {
            exceptionThrown = ex;
        }
        int written = 0;
        if (exceptionThrown == null)
        {
            try
            {
                written += processBytes(input, inOff, len, output, outOff);
                written += doFinal(output, written + outOff);
            }
            catch (Throwable t)
            {
                exceptionThrown = t;
            }
        }

        //reset
        if (cipher != null)
        {
            cipher.reset();
            Arrays.fill(nonce, (byte)0);
            Arrays.fill(S, (byte)0);
            Arrays.fill(S_at, (byte)0);
            Arrays.fill(S_atPre, (byte)0);
            Arrays.fill(atBlock, (byte)0);
        }


        atBlockPos = 0;
        atLength = 0;
        atLengthPre = 0;
        counter = Arrays.clone(J0);
        blocksRemaining = 0;
        bufOff = 0;
        totalLength = 0;
        if (bufBlock != null)
        {
            Arrays.fill(bufBlock, (byte)0);
        }
        if (macBlock != null)
        {
            Arrays.fill(macBlock, (byte)0);
        }

        if (exceptionThrown != null)
        {
            Arrays.fill(output, (byte)0);
            throw PacketCipherException.from(exceptionThrown);
        }
        return written;
    }

    private int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        int resultLen = 0;

        if (forEncryption)
        {
            if (bufOff > 0)
            {
                int available = BLOCK_SIZE - bufOff;
                if (len < available)
                {
                    System.arraycopy(in, inOff, bufBlock, bufOff, len);
                    bufOff += len;
                    return 0;
                }

                System.arraycopy(in, inOff, bufBlock, bufOff, available);
                encryptBlock(bufBlock, 0, out, outOff);
                inOff += available;
                len -= available;
                resultLen = BLOCK_SIZE;
            }

            int inLimit = inOff + len - BLOCK_SIZE;

            while (inOff <= inLimit)
            {
                encryptBlock(in, inOff, out, outOff + resultLen);
                inOff += BLOCK_SIZE;
                resultLen += BLOCK_SIZE;
            }

            bufOff = BLOCK_SIZE + inLimit - inOff;
            System.arraycopy(in, inOff, bufBlock, 0, bufOff);
        }
        else
        {
            int available = bufBlock.length - bufOff;
            if (len < available)
            {
                System.arraycopy(in, inOff, bufBlock, bufOff, len);
                bufOff += len;
                return 0;
            }

            if (bufOff >= BLOCK_SIZE)
            {
                decryptBlock(bufBlock, 0, out, outOff);
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, bufOff -= BLOCK_SIZE);
                resultLen = BLOCK_SIZE;

                available += BLOCK_SIZE;
                if (len < available)
                {
                    System.arraycopy(in, inOff, bufBlock, bufOff, len);
                    bufOff += len;
                    return resultLen;
                }
            }

            int inLimit = inOff + len - bufBlock.length;

            available = BLOCK_SIZE - bufOff;
            System.arraycopy(in, inOff, bufBlock, bufOff, available);
            decryptBlock(bufBlock, 0, out, outOff + resultLen);
            inOff += available;
            resultLen += BLOCK_SIZE;
            //bufOff = 0;

            while (inOff <= inLimit)
            {
                decryptBlock(in, inOff, out, outOff + resultLen);
                inOff += BLOCK_SIZE;
                resultLen += BLOCK_SIZE;
            }

            bufOff = bufBlock.length + inLimit - inOff;
            System.arraycopy(in, inOff, bufBlock, 0, bufOff);
        }

        return resultLen;
    }


    private void gHASHBlock(byte[] Y, byte[] b)
    {
        GCMUtil.xor(Y, b);
        multiplier.multiplyH(Y);
    }

    private void gHASHBlock(byte[] Y, byte[] b, int off)
    {
        GCMUtil.xor(Y, b, off);
        multiplier.multiplyH(Y);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len)
    {
        GCMUtil.xor(Y, b, off, len);
        multiplier.multiplyH(Y);
    }

    private void getNextCTRBlock(byte[] block)
    {
        if (blocksRemaining == 0)
        {
            throw new IllegalStateException("Attempt to process too many blocks");
        }
        blocksRemaining--;

        int c = 1;
        c += counter[15] & 0xFF;
        counter[15] = (byte)c;
        c >>>= 8;
        c += counter[14] & 0xFF;
        counter[14] = (byte)c;
        c >>>= 8;
        c += counter[13] & 0xFF;
        counter[13] = (byte)c;
        c >>>= 8;
        c += counter[12] & 0xFF;
        counter[12] = (byte)c;

        cipher.processBlock(counter, 0, block, 0);
    }

    private void processAADBytes(byte[] in, int inOff, int len)
    {
        if (atBlockPos > 0)
        {
            int available = BLOCK_SIZE - atBlockPos;
            if (len < available)
            {
                System.arraycopy(in, inOff, atBlock, atBlockPos, len);
                atBlockPos += len;
                return;
            }

            System.arraycopy(in, inOff, atBlock, atBlockPos, available);
            gHASHBlock(S_at, atBlock);
            atLength += BLOCK_SIZE;
            inOff += available;
            len -= available;
        }

        int inLimit = inOff + len - BLOCK_SIZE;

        while (inOff <= inLimit)
        {
            gHASHBlock(S_at, in, inOff);
            atLength += BLOCK_SIZE;
            inOff += BLOCK_SIZE;
        }

        atBlockPos = BLOCK_SIZE + inLimit - inOff;
        System.arraycopy(in, inOff, atBlock, 0, atBlockPos);
    }

    private void encryptBlock(byte[] buf, int bufOff, byte[] out, int outOff)
    {
        if (totalLength == 0)
        {
            initCipher();
        }

        byte[] ctrBlock = new byte[BLOCK_SIZE];

        getNextCTRBlock(ctrBlock);
        GCMUtil.xor(ctrBlock, buf, bufOff);
        gHASHBlock(S, ctrBlock);
        System.arraycopy(ctrBlock, 0, out, outOff, BLOCK_SIZE);

        totalLength += BLOCK_SIZE;
    }

    private void decryptBlock(byte[] buf, int bufOff, byte[] out, int outOff)
    {
        if (totalLength == 0)
        {
            initCipher();
        }

        byte[] ctrBlock = new byte[BLOCK_SIZE];
        getNextCTRBlock(ctrBlock);

        gHASHBlock(S, buf, bufOff);
        GCMUtil.xor(ctrBlock, 0, buf, bufOff, out, outOff);

        totalLength += BLOCK_SIZE;
    }

    private void initCipher()
    {
        if (atLength > 0)
        {
            System.arraycopy(S_at, 0, S_atPre, 0, BLOCK_SIZE);
            atLengthPre = atLength;
        }

        // Finish hash for partial AAD block
        if (atBlockPos > 0)
        {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos);
            atLengthPre += atBlockPos;
        }

        if (atLengthPre > 0)
        {
            System.arraycopy(S_atPre, 0, S, 0, BLOCK_SIZE);
        }
    }

    private int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (totalLength == 0)
        {
            initCipher();
        }

        int extra = bufOff;

        if (!forEncryption)
        {
            extra -= macSize;
        }

        if (extra > 0)
        {
            byte[] ctrBlock = new byte[BLOCK_SIZE];
            getNextCTRBlock(ctrBlock);
            if (forEncryption)
            {
                GCMUtil.xor(bufBlock, 0, ctrBlock, 0, extra);
                gHASHPartial(S, bufBlock, 0, extra);
            }
            else
            {
                gHASHPartial(S, bufBlock, 0, extra);
                GCMUtil.xor(bufBlock, 0, ctrBlock, 0, extra);
            }

            System.arraycopy(bufBlock, 0, out, outOff, extra);
            totalLength += extra;
        }

        atLength += atBlockPos;

        if (atLength > atLengthPre)
        {
            /*
             *  Some AAD was sent after the cipher started. We determine the difference b/w the hash value
             *  we actually used when the cipher started (S_atPre) and the final hash value calculated (S_at).
             *  Then we carry this difference forward by multiplying by H^c, where c is the number of (full or
             *  partial) cipher-text blocks produced, and adjust the current hash.
             */

            // Finish hash for partial AAD block
            if (atBlockPos > 0)
            {
                gHASHPartial(S_at, atBlock, 0, atBlockPos);
            }

            // Find the difference between the AAD hashes
            if (atLengthPre > 0)
            {
                GCMUtil.xor(S_at, S_atPre);
            }

            // Number of cipher-text blocks produced
            long c = ((totalLength * 8) + 127) >>> 7;

            // Calculate the adjustment factor
            byte[] H_c = new byte[16];
            if (exp == null)
            {
                exp = new BasicGCMExponentiator();
                exp.init(H);
            }
            exp.exponentiateX(c, H_c);

            // Carry the difference forward
            GCMUtil.multiply(S_at, H_c);

            // Adjust the current hash
            GCMUtil.xor(S, S_at);
        }

        // Final gHASH
        byte[] X = new byte[BLOCK_SIZE];
        Pack.longToBigEndian(atLength * 8, X, 0);
        Pack.longToBigEndian(totalLength * 8, X, 8);

        gHASHBlock(S, X);

        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tag, 0);
        GCMUtil.xor(tag, S);

        int resultLen = extra;

        if (forEncryption)
        {
            // Append T to the message
            System.arraycopy(tag, 0, out, outOff + bufOff, macSize);
            resultLen += macSize;
        }
        else
        {
            // We place into macBlock our calculated value for T
            macBlock = new byte[macSize];
            System.arraycopy(tag, 0, macBlock, 0, macSize);
            // Retrieve the T value from the message and compare to calculated one
            byte[] msgMac = new byte[macSize];
            System.arraycopy(bufBlock, extra, msgMac, 0, macSize);
            if (!Arrays.constantTimeAreEqual(macBlock, msgMac))
            {
                throw new InvalidCipherTextException("mac check in GCM failed");
            }
        }
        return resultLen;
    }
}
