package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class AESGCMPacketCipher
    implements PacketCipher
{
    private static final int BLOCK_SIZE = 16;

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
        return len < macSize ? 0 : len - macSize;
    }


    @Override
    public int processPacket(boolean forEncryption, CipherParameters params, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
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
        //Tables4kGCMMultiplier
        byte[] H;
        long[][] T = null;
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
                if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
                {
                    throw new IllegalArgumentException(ExceptionMessage.AES_KEY_LENGTH);
                }
                KC = keyLen >>> 2;
                ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
                workingKey = generateWorkingKey(keyParam.getKey(), KC, ROUNDS);
                s = Arrays.clone(S);
                HGCM = new byte[BLOCK_SIZE];
                encryptBlock(HGCM, HGCM, workingKey, s, ROUNDS);

                // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
                T = new long[256][2];
                H = new byte[BLOCK_SIZE];
                System.arraycopy(HGCM, 0, H, 0, BLOCK_SIZE);
                // T[1] = H.p^7
                GCMUtil.asLongs(H, T[1]);
                GCMUtil.multiplyP7(T[1], T[1]);
                for (int n = 2; n < 256; n += 2)
                {
                    // T[2.n] = T[n].p^-1
                    GCMUtil.divideP(T[n >> 1], T[n]);
                    // T[2.n + 1] = T[2.n] + T[1]
                    GCMUtil.xor(T[n], T[1], T[n + 1]);
                }
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

        if (exceptionThrown != null)
        {
            Arrays.fill(output, (byte)0);
            throw PacketCipherException.from(exceptionThrown);
        }
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

    private void multiplyH(byte[] x, long[][] T)
    {
        long[] t = T[x[15] & 0xFF];
        long z0 = t[0], z1 = t[1];

        for (int i = 14; i >= 0; --i)
        {
            t = T[x[i] & 0xFF];

            long c = z1 << 56;
            z1 = t[1] ^ ((z1 >>> 8) | (z0 << 56));
            z0 = t[0] ^ (z0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        }

        Pack.longToBigEndian(z0, x, 0);
        Pack.longToBigEndian(z1, x, 8);
    }

    private void gHASHBlock(byte[] Y, byte[] b, long[][] T)
    {
        GCMUtil.xor(Y, b);
        multiplyH(Y, T);
        //multiplier.multiplyH(Y);
    }

    private void gHASHBlock(byte[] Y, byte[] b, int off, long[][] T)
    {
        GCMUtil.xor(Y, b, off);
        multiplyH(Y, T);
        //multiplier.multiplyH(Y);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len, long[][] T)
    {
        GCMUtil.xor(Y, b, off, len);
        multiplyH(Y, T);
        //multiplier.multiplyH(Y);
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

        //cipher.processBlock(counter, 0, block, 0);
        encryptBlock(counter, block, workingkey, s, ROUNDS);
        return blocksRemaining;
    }

    private int[][] generateWorkingKey(byte[] key, int KC, int ROUNDS)
    {
        int[][] W = new int[ROUNDS + 1][4];   // 4 words in a block
        int col0 = Pack.littleEndianToInt(key, 0);
        W[0][0] = col0;
        int col1 = Pack.littleEndianToInt(key, 4);
        W[0][1] = col1;
        int col2 = Pack.littleEndianToInt(key, 8);
        W[0][2] = col2;
        int col3 = Pack.littleEndianToInt(key, 12);
        W[0][3] = col3;
        switch (KC)
        {
        case 4:
        {
            for (int i = 1; i <= 10; ++i)
            {
                int colx = subWord(shift(col3, 8)) ^ rcon[i - 1];
                col0 ^= colx;
                W[i][0] = col0;
                col1 ^= col0;
                W[i][1] = col1;
                col2 ^= col1;
                W[i][2] = col2;
                col3 ^= col2;
                W[i][3] = col3;
            }
            break;
        }
        case 6:
        {
            int col4 = Pack.littleEndianToInt(key, 16);
            int col5 = Pack.littleEndianToInt(key, 20);

            int i = 1, rcon = 1, colx;
            for (; ; )
            {
                W[i][0] = col4;
                W[i][1] = col5;
                colx = subWord(shift(col5, 8)) ^ rcon;
                rcon <<= 1;
                col0 ^= colx;
                W[i][2] = col0;
                col1 ^= col0;
                W[i][3] = col1;

                col2 ^= col1;
                W[i + 1][0] = col2;
                col3 ^= col2;
                W[i + 1][1] = col3;
                col4 ^= col3;
                W[i + 1][2] = col4;
                col5 ^= col4;
                W[i + 1][3] = col5;

                colx = subWord(shift(col5, 8)) ^ rcon;
                rcon <<= 1;
                col0 ^= colx;
                W[i + 2][0] = col0;
                col1 ^= col0;
                W[i + 2][1] = col1;
                col2 ^= col1;
                W[i + 2][2] = col2;
                col3 ^= col2;
                W[i + 2][3] = col3;

                if ((i += 3) >= 13)
                {
                    break;
                }

                col4 ^= col3;
                col5 ^= col4;
            }

            break;
        }
        case 8:
        {
            int col4 = Pack.littleEndianToInt(key, 16);
            W[1][0] = col4;
            int col5 = Pack.littleEndianToInt(key, 20);
            W[1][1] = col5;
            int col6 = Pack.littleEndianToInt(key, 24);
            W[1][2] = col6;
            int col7 = Pack.littleEndianToInt(key, 28);
            W[1][3] = col7;
            int i = 2, rcon = 1, colx;
            for (; ; )
            {
                colx = subWord(shift(col7, 8)) ^ rcon;
                rcon <<= 1;
                col0 ^= colx;
                W[i][0] = col0;
                col1 ^= col0;
                W[i][1] = col1;
                col2 ^= col1;
                W[i][2] = col2;
                col3 ^= col2;
                W[i][3] = col3;
                ++i;
                if (i >= 15)
                {
                    break;
                }
                colx = subWord(col3);
                col4 ^= colx;
                W[i][0] = col4;
                col5 ^= col4;
                W[i][1] = col5;
                col6 ^= col5;
                W[i][2] = col6;
                col7 ^= col6;
                W[i][3] = col7;
                ++i;
            }
            break;
        }
        default:
        {
            throw new IllegalStateException("Should never get here");
        }
        }
        return W;
    }

    private static final byte[] S = {
        (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
        (byte)48, (byte)1, (byte)103, (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250, (byte)89, (byte)71, (byte)240,
        (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147, (byte)38, (byte)54, (byte)63, (byte)247, (byte)204,
        (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216, (byte)49, (byte)21,
        (byte)4, (byte)199, (byte)35, (byte)195, (byte)24, (byte)150, (byte)5, (byte)154,
        (byte)7, (byte)18, (byte)128, (byte)226, (byte)235, (byte)39, (byte)178, (byte)117,
        (byte)9, (byte)131, (byte)44, (byte)26, (byte)27, (byte)110, (byte)90, (byte)160,
        (byte)82, (byte)59, (byte)214, (byte)179, (byte)41, (byte)227, (byte)47, (byte)132,
        (byte)83, (byte)209, (byte)0, (byte)237, (byte)32, (byte)252, (byte)177, (byte)91,
        (byte)106, (byte)203, (byte)190, (byte)57, (byte)74, (byte)76, (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251, (byte)67, (byte)77, (byte)51, (byte)133,
        (byte)69, (byte)249, (byte)2, (byte)127, (byte)80, (byte)60, (byte)159, (byte)168,
        (byte)81, (byte)163, (byte)64, (byte)143, (byte)146, (byte)157, (byte)56, (byte)245,
        (byte)188, (byte)182, (byte)218, (byte)33, (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205, (byte)12, (byte)19, (byte)236, (byte)95, (byte)151, (byte)68, (byte)23,
        (byte)196, (byte)167, (byte)126, (byte)61, (byte)100, (byte)93, (byte)25, (byte)115,
        (byte)96, (byte)129, (byte)79, (byte)220, (byte)34, (byte)42, (byte)144, (byte)136,
        (byte)70, (byte)238, (byte)184, (byte)20, (byte)222, (byte)94, (byte)11, (byte)219,
        (byte)224, (byte)50, (byte)58, (byte)10, (byte)73, (byte)6, (byte)36, (byte)92,
        (byte)194, (byte)211, (byte)172, (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200, (byte)55, (byte)109, (byte)141, (byte)213, (byte)78, (byte)169,
        (byte)108, (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174, (byte)8,
        (byte)186, (byte)120, (byte)37, (byte)46, (byte)28, (byte)166, (byte)180, (byte)198,
        (byte)232, (byte)221, (byte)116, (byte)31, (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112, (byte)62, (byte)181, (byte)102, (byte)72, (byte)3, (byte)246, (byte)14,
        (byte)97, (byte)53, (byte)87, (byte)185, (byte)134, (byte)193, (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152, (byte)17, (byte)105, (byte)217, (byte)142, (byte)148,
        (byte)155, (byte)30, (byte)135, (byte)233, (byte)206, (byte)85, (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137, (byte)13, (byte)191, (byte)230, (byte)66, (byte)104,
        (byte)65, (byte)153, (byte)45, (byte)15, (byte)176, (byte)84, (byte)187, (byte)22,
    };

    // vector used in calculating key schedule (powers of x in GF(256))
    private static final int[] rcon = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

    // precomputation tables of calculations for rounds
    private static final int[] T0 =
        {
            0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff,
            0xbd6b6bd6, 0xb16f6fde, 0x54c5c591, 0x50303060, 0x03010102,
            0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d,
            0x9a7676ec, 0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
            0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb, 0xecadad41,
            0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
            0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d,
            0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
            0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2,
            0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795,
            0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a,
            0xb59a9a2f, 0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
            0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912,
            0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc,
            0xee5a5ab4, 0xfba0a05b, 0xf65252a4, 0x4d3b3b76, 0x61d6d6b7,
            0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
            0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040,
            0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
            0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0,
            0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
            0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511, 0xcf45458a,
            0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78,
            0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d, 0xc0404080,
            0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
            0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020,
            0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18,
            0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488,
            0x3917172e, 0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
            0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6, 0xa06060c0,
            0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
            0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b,
            0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
            0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992,
            0x0a06060c, 0x6c242448, 0xe45c5cb8, 0x5dc2c29f, 0x6ed3d3bd,
            0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3,
            0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
            0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8,
            0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4,
            0xe9aeae47, 0x18080810, 0xd5baba6f, 0x887878f0, 0x6f25254a,
            0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
            0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96,
            0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
            0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7,
            0x120e0e1c, 0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
            0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27, 0x38e1e1d9,
            0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9,
            0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c, 0x92878715,
            0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
            0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65,
            0x31e6e6d7, 0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929,
            0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d,
            0x3a16162c};

    private static int shift(int r, int shift)
    {
        return (r >>> shift) | (r << -shift);
    }

    private static int subWord(int x)
    {
        return (S[x & 255] & 255 | ((S[(x >> 8) & 255] & 255) << 8) | ((S[(x >> 16) & 255] & 255) << 16) | S[(x >> 24) & 255] << 24);
    }

    private void encryptBlock(byte[] in, byte[] out, int[][] KW, byte[] s, int ROUNDS)
    {
        int C0 = Pack.littleEndianToInt(in, 0);
        int C1 = Pack.littleEndianToInt(in, 4);
        int C2 = Pack.littleEndianToInt(in, 8);
        int C3 = Pack.littleEndianToInt(in, 12);
        int t0 = C0 ^ KW[0][0];
        int t1 = C1 ^ KW[0][1];
        int t2 = C2 ^ KW[0][2];
        int r = 1, r0, r1, r2, r3 = C3 ^ KW[0][3];
        while (r < ROUNDS - 1)
        {
            r0 = T0[t0 & 255] ^ shift(T0[(t1 >> 8) & 255], 24) ^ shift(T0[(t2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
            r1 = T0[t1 & 255] ^ shift(T0[(t2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(t0 >> 24) & 255], 8) ^ KW[r][1];
            r2 = T0[t2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(t0 >> 16) & 255], 16) ^ shift(T0[(t1 >> 24) & 255], 8) ^ KW[r][2];
            r3 = T0[r3 & 255] ^ shift(T0[(t0 >> 8) & 255], 24) ^ shift(T0[(t1 >> 16) & 255], 16) ^ shift(T0[(t2 >> 24) & 255], 8) ^ KW[r++][3];
            t0 = T0[r0 & 255] ^ shift(T0[(r1 >> 8) & 255], 24) ^ shift(T0[(r2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
            t1 = T0[r1 & 255] ^ shift(T0[(r2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(r0 >> 24) & 255], 8) ^ KW[r][1];
            t2 = T0[r2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(r0 >> 16) & 255], 16) ^ shift(T0[(r1 >> 24) & 255], 8) ^ KW[r][2];
            r3 = T0[r3 & 255] ^ shift(T0[(r0 >> 8) & 255], 24) ^ shift(T0[(r1 >> 16) & 255], 16) ^ shift(T0[(r2 >> 24) & 255], 8) ^ KW[r++][3];
        }
        r0 = T0[t0 & 255] ^ shift(T0[(t1 >> 8) & 255], 24) ^ shift(T0[(t2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
        r1 = T0[t1 & 255] ^ shift(T0[(t2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(t0 >> 24) & 255], 8) ^ KW[r][1];
        r2 = T0[t2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(t0 >> 16) & 255], 16) ^ shift(T0[(t1 >> 24) & 255], 8) ^ KW[r][2];
        r3 = T0[r3 & 255] ^ shift(T0[(t0 >> 8) & 255], 24) ^ shift(T0[(t1 >> 16) & 255], 16) ^ shift(T0[(t2 >> 24) & 255], 8) ^ KW[r++][3];
        // the final round's table is a simple function of S so we don't use a whole other four tables for it
        C0 = (S[r0 & 255] & 255) ^ ((S[(r1 >> 8) & 255] & 255) << 8) ^ ((s[(r2 >> 16) & 255] & 255) << 16) ^ (s[(r3 >> 24) & 255] << 24) ^ KW[r][0];
        C1 = (s[r1 & 255] & 255) ^ ((S[(r2 >> 8) & 255] & 255) << 8) ^ ((S[(r3 >> 16) & 255] & 255) << 16) ^ (s[(r0 >> 24) & 255] << 24) ^ KW[r][1];
        C2 = (s[r2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(r0 >> 16) & 255] & 255) << 16) ^ (S[(r1 >> 24) & 255] << 24) ^ KW[r][2];
        C3 = (s[r3 & 255] & 255) ^ ((s[(r0 >> 8) & 255] & 255) << 8) ^ ((s[(r1 >> 16) & 255] & 255) << 16) ^ (S[(r2 >> 24) & 255] << 24) ^ KW[r][3];
        Pack.intToLittleEndian(C0, out, 0);
        Pack.intToLittleEndian(C1, out, 4);
        Pack.intToLittleEndian(C2, out, 8);
        Pack.intToLittleEndian(C3, out, 12);
    }
}
