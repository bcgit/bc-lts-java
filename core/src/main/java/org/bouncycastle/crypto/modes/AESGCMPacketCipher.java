package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESGCMPacketCipher
    extends PacketCipherEngine
    implements AESGCMModePacketCipher
{
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
            if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            macSize = macSizeBits >> 3;

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
        else if (len < macSize)
        {
            throw new DataLengthException(ExceptionMessage.OUTPUT_LENGTH);
        }
        return len - macSize;
    }


    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
        processPacketExceptionCheck(input, inOff, len, output, outOff);

        // These fields are set by init and not modified by processing
        int macSize = 0;
        byte[] nonce = null;
        byte[] HGCM = null;
        byte[] J0 = null;

        // These fields are modified during processing
        byte[] bufBlock = null;
        byte[] macBlock = null;
        byte[] S_current = null, S_at = null, S_atPre = null;
        byte[] counter = null;
        int blocksRemaining = 0;
        int bufOff = 0;
        long totalLength = 0;
        byte[] atBlock = null;
        int atBlockPos = 0;
        long atLength = 0;
        long atLengthPre = 0;
        Throwable exceptionThrown = null;
        int KC, ROUNDS = 0;
        int[][] workingKey = null;
        byte[] s = null;
        long[][] T = new long[256][2];
        try
        {
            KeyParameter keyParam;
            byte[] newNonce;
            byte[] initialAssociatedText;
            if (params instanceof AEADParameters)
            {
                AEADParameters param = (AEADParameters)params;
                newNonce = param.getNonce();
                initialAssociatedText = param.getAssociatedText();

                int macSizeBits = param.getMacSize();
                if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
                {
                    throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
                }

                macSize = macSizeBits >> 3;
                keyParam = param.getKey();
            }
            else if (params instanceof ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV)params;

                newNonce = param.getIV().clone();
                initialAssociatedText = null;
                macSize = 16;
                keyParam = (KeyParameter)param.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("invalid parameters passed to GCM");
            }
            AEADLengthCheck(forEncryption, len, output, outOff, macSize);
            int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize);
            bufBlock = new byte[bufLength];

            if (newNonce == null || newNonce.length < 12)
            {
                throw new IllegalArgumentException("IV must be at least 12 byte");
            }

            nonce = newNonce;

            // TODO Restrict macSize to 16 if nonce length not 12?

            // Cipher always used in forward mode
            // if keyParam is null we're reusing the last key.
            if (keyParam != null)
            {
                int keyLen = keyParam.getKey().length;
                checkKeyLength(keyLen);
                KC = keyLen >>> 2;
                ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
                workingKey = generateWorkingKey(keyParam.getKey(), KC, ROUNDS);
                s = Arrays.clone(S);
                HGCM = new byte[BLOCK_SIZE];
                encryptBlock(HGCM, HGCM, workingKey, s, ROUNDS);
                GCMInitialT(T, HGCM);
            }
            else
            {
                throw new IllegalArgumentException("Key must be specified in initial init");
            }

            J0 = new byte[BLOCK_SIZE];

            if (nonce.length == 12)
            {
                System.arraycopy(nonce, 0, J0, 0, nonce.length);
                J0[BLOCK_SIZE - 1] = 0x01;
            }
            else
            {
                //gHASH
                for (int pos = 0; pos < nonce.length; pos += BLOCK_SIZE)
                {
                    int num = Math.min(nonce.length - pos, BLOCK_SIZE);
                    gHASHPartial(J0, nonce, pos, num, T);
                }
                byte[] X = new byte[BLOCK_SIZE];
                Pack.longToBigEndian((long)nonce.length << 3, X, 8);
                gHASHBlock(J0, X, T);
            }
            S_current = new byte[BLOCK_SIZE];
            S_at = new byte[BLOCK_SIZE];
            S_atPre = new byte[BLOCK_SIZE];
            atBlock = new byte[BLOCK_SIZE];
            counter = Arrays.clone(J0);
            blocksRemaining = -2;      // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
            if (initialAssociatedText != null)
            {
                int aadLen = initialAssociatedText.length;
                int aadOff = 0;
                int inLimit = aadOff + aadLen - BLOCK_SIZE;
                while (aadOff <= inLimit)
                {
                    gHASHBlock(S_at, initialAssociatedText, aadOff, T);
                    atLength += BLOCK_SIZE;
                    aadOff += BLOCK_SIZE;
                }
                atBlockPos = BLOCK_SIZE + inLimit - aadOff;
                System.arraycopy(initialAssociatedText, aadOff, atBlock, 0, atBlockPos);
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
                boolean processContinue = true;
                if (forEncryption)
                {
                    int inLimit = inOff + len - BLOCK_SIZE;
                    while (inOff <= inLimit)
                    {
                        if (totalLength == 0)
                        {
                            atLengthPre = getAtLengthPre(S_at, S_atPre, atLength, atLengthPre);
                            atLengthPre = getAtLengthPre(T, S_atPre, atBlock, atBlockPos, atLengthPre);
                            extracted(S_current, S_atPre, atLengthPre);
                        }
                        byte[] ctrBlock = new byte[BLOCK_SIZE];
                        blocksRemaining = getNextCTRBlock(ctrBlock, blocksRemaining, counter, workingKey, s, ROUNDS);
                        GCMUtil.xor(ctrBlock, input, inOff);
                        gHASHBlock(S_current, ctrBlock, T);
                        System.arraycopy(ctrBlock, 0, output, outOff + written, BLOCK_SIZE);
                        totalLength += BLOCK_SIZE;

                        inOff += BLOCK_SIZE;
                        written += BLOCK_SIZE;
                    }
                    bufOff = BLOCK_SIZE + inLimit - inOff;
                    System.arraycopy(input, inOff, bufBlock, 0, bufOff);
                }
                else
                {
                    int available = bufBlock.length - bufOff;
                    if (len < available)
                    {
                        System.arraycopy(input, inOff, bufBlock, bufOff, len);
                        bufOff += len;
                        processContinue = false;
                    }
                    if (processContinue)
                    {
                        int inLimit = inOff + len - bufBlock.length;
                        available = BLOCK_SIZE - bufOff;
                        System.arraycopy(input, inOff, bufBlock, bufOff, available);
                        atLengthPre = getAtLengthPre(S_at, S_atPre, atLength, atLengthPre);
                        atLengthPre = getAtLengthPre(T, S_atPre, atBlock, atBlockPos, atLengthPre);
                        extracted(S_current, S_atPre, atLengthPre);
                        byte[] ctrBlock = new byte[BLOCK_SIZE];
                        blocksRemaining = getNextCTRBlock(ctrBlock, blocksRemaining, counter, workingKey, s, ROUNDS);
                        gHASHBlock(S_current, bufBlock, 0, T);
                        GCMUtil.xor(ctrBlock, 0, bufBlock, bufOff, output, outOff + written);
                        totalLength += BLOCK_SIZE;

                        inOff += available;
                        written += BLOCK_SIZE;
                        while (inOff <= inLimit)
                        {
                            //decryptBlock(input, inOff, output, outOff + written);
                            if (totalLength == 0)
                            {
                                atLengthPre = getAtLengthPre(S_at, S_atPre, atLength, atLengthPre);
                                atLengthPre = getAtLengthPre(T, S_atPre, atBlock, atBlockPos, atLengthPre);
                                extracted(S_current, S_atPre, atLengthPre);
                            }
                            ctrBlock = new byte[BLOCK_SIZE];
                            blocksRemaining = getNextCTRBlock(ctrBlock, blocksRemaining, counter, workingKey, s, ROUNDS);
                            gHASHBlock(S_current, input, inOff, T);
                            GCMUtil.xor(ctrBlock, 0, input, inOff, output, outOff + written);
                            totalLength += BLOCK_SIZE;

                            inOff += BLOCK_SIZE;
                            written += BLOCK_SIZE;
                        }

                        bufOff = bufBlock.length + inLimit - inOff;
                        System.arraycopy(input, inOff, bufBlock, 0, bufOff);
                    }
                }
                //written += doFinal(output, written + outOff);
                if (totalLength == 0)
                {
                    //initCipher();
                    atLengthPre = getAtLengthPre(S_at, S_atPre, atLength, atLengthPre);
                    atLengthPre = getAtLengthPre(T, S_atPre, atBlock, atBlockPos, atLengthPre);
                    extracted(S_current, S_atPre, atLengthPre);
                }
                int extra = bufOff;
                if (!forEncryption)
                {
                    extra -= macSize;
                }
                if (extra > 0)
                {
                    byte[] ctrBlock = new byte[BLOCK_SIZE];
                    getNextCTRBlock(ctrBlock, blocksRemaining, counter, workingKey, s, ROUNDS);
                    if (forEncryption)
                    {
                        GCMUtil.xor(bufBlock, 0, ctrBlock, 0, extra);
                        gHASHPartial(S_current, bufBlock, 0, extra, T);
                    }
                    else
                    {
                        gHASHPartial(S_current, bufBlock, 0, extra, T);
                        GCMUtil.xor(bufBlock, 0, ctrBlock, 0, extra);
                    }
                    System.arraycopy(bufBlock, 0, output, outOff + written, extra);
                    totalLength += extra;
                }
                atLength += atBlockPos;
                if (atLength > atLengthPre)
                {
                    /*
                     *  Some AAD was sent after the cipher started. We determine the difference b/w the hash value
                     *  we actually used when the cipher started (S_atPre) and the final hash value calculated (S_at).
                     *  Then we carry this difference forward by multiplying by HGCM^c, where c is the number of (full or
                     *  partial) cipher-text blocks produced, and adjust the current hash.
                     */
                    // Finish hash for partial AAD block
                    if (atBlockPos > 0)
                    {
                        gHASHPartial(S_at, atBlock, 0, atBlockPos, T);
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
                    long[] x = GCMUtil.asLongs(HGCM);
                    long[] y = GCMUtil.oneAsLongs();
                    if (c > 0)
                    {
                        long[] powX = new long[GCMUtil.SIZE_LONGS];
                        System.arraycopy(x, 0, powX, 0, GCMUtil.SIZE_LONGS);
                        do
                        {
                            if ((c & 1L) != 0)
                            {
                                GCMUtil.multiply(y, powX);
                            }
                            GCMUtil.square(powX, powX);
                            c >>>= 1;
                        }
                        while (c > 0);
                    }
                    GCMUtil.asBytes(y, H_c);
                    // Carry the difference forward
                    GCMUtil.multiply(S_at, H_c);
                    // Adjust the current hash
                    GCMUtil.xor(S_current, S_at);
                }

                // Final gHASH
                byte[] X = new byte[BLOCK_SIZE];
                Pack.longToBigEndian(atLength * 8, X, 0);
                Pack.longToBigEndian(totalLength * 8, X, 8);
                gHASHBlock(S_current, X, T);
                // T = MSBt(GCTRk(J0,S))
                byte[] tag = new byte[BLOCK_SIZE];
                //cipher.processBlock(J0, 0, tag, 0);
                encryptBlock(J0, tag, workingKey, s, ROUNDS);
                GCMUtil.xor(tag, S_current);
                written += extra;
                if (forEncryption)
                {
                    // Append T to the message
                    System.arraycopy(tag, 0, output, outOff + written, macSize);
                    written += macSize;
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
            }
            catch (Throwable t)
            {
                exceptionThrown = t;
            }
        }

        //reset
        if (workingKey != null)
        {
            for (int[] ints : workingKey)
            {
                Arrays.fill(ints, 0);
            }
        }
        if (nonce != null)
        {
            Arrays.fill(nonce, (byte)0);
        }
        if (S_current != null)
        {
            Arrays.fill(S_current, (byte)0);
            Arrays.fill(S_at, (byte)0);
            Arrays.fill(S_atPre, (byte)0);
            Arrays.fill(atBlock, (byte)0);
        }
        if (bufBlock != null)
        {
            Arrays.fill(bufBlock, (byte)0);
        }
        if (macBlock != null)
        {
            Arrays.fill(macBlock, (byte)0);
        }

        AEADExceptionHandler(output, outOff, exceptionThrown, written);
        return written;
    }



    private static void extracted(byte[] S, byte[] S_atPre, long atLengthPre)
    {
        if (atLengthPre > 0)
        {
            System.arraycopy(S_atPre, 0, S, 0, BLOCK_SIZE);
        }
    }

    private long getAtLengthPre(long[][] T, byte[] S_atPre, byte[] atBlock, int atBlockPos, long atLengthPre)
    {
        // Finish hash for partial AAD block
        if (atBlockPos > 0)
        {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos, T);
            atLengthPre += atBlockPos;
        }
        return atLengthPre;
    }

    private static long getAtLengthPre(byte[] S_at, byte[] S_atPre, long atLength, long atLengthPre)
    {
        if (atLength > 0)
        {
            System.arraycopy(S_at, 0, S_atPre, 0, BLOCK_SIZE);
            atLengthPre = atLength;
        }
        return atLengthPre;
    }

    private void gHASHBlock(byte[] Y, byte[] b, long[][] T)
    {
        GCMUtil.xor(Y, b);
        multiplyH(Y, T);
    }

    private void gHASHBlock(byte[] Y, byte[] b, int off, long[][] T)
    {
        GCMUtil.xor(Y, b, off);
        multiplyH(Y, T);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len, long[][] T)
    {
        GCMUtil.xor(Y, b, off, len);
        multiplyH(Y, T);
    }

    private int getNextCTRBlock(byte[] block, int blocksRemaining, byte[] counter, int[][] workingkey, byte[] s, int ROUNDS)
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

        encryptBlock(counter, block, workingkey, s, ROUNDS);
        return blocksRemaining;
    }

    @Override
    public String toString()
    {
        return "GCM Packet Cipher";
    }
}
