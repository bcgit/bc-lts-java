package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeGCMPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import javax.security.auth.DestroyFailedException;

public class AESGCMPacketCipher
        extends AESPacketCipherEngine
        implements AESGCMModePacketCipher
{
    private boolean destroyed = false;

    public static AESGCMModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM_PC))
        {
            return new AESNativeGCMPacketCipher();
        }
        return new AESGCMPacketCipher();
    }

    public AESGCMPacketCipher()
    {

    }


    @Override
    public int getOutputSize(boolean forEncryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }
        int macSize = checkParameters(parameters);
        if (forEncryption)
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
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, final int len,
                             byte[] output, int outOff) throws PacketCipherException
    {

        // Output len varies with direction.
        PacketCipherChecks.checkBoundsInput(input, inOff, len, output, outOff);

        final byte[] keyOwned;
        final byte[] nonceOwned;
        final byte[] ad;
        final int macSizeBytes;
        final long[][] mulT = new long[256][2];
        final int blockSize = AESPacketCipher.BLOCK_SIZE;
        final int outOffStart = outOff;

        if (parameters instanceof AEADParameters)
        {
            AEADParameters aeadParam = (AEADParameters) parameters;
            nonceOwned = aeadParam.getNonce(); // This does a clone
            ad = aeadParam.getAssociatedText();
            int macSizeBits = aeadParam.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || (macSizeBits & 7) != 0)
            {
                throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.GCM_INVALID_MAC_SIZE + macSizeBits));
            }
            macSizeBytes = macSizeBits >> 3;
            PacketCipherChecks.checkKeyLength(aeadParam.getKey().getKeyLength());
            keyOwned = Arrays.clone(aeadParam.getKey().getKey());
        }
        else if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV) parameters;

            nonceOwned = Arrays.clone(param.getIV());
            ad = null;
            macSizeBytes = 16;
            PacketCipherChecks.checkKeyLength(((KeyParameter) param.getParameters()).getKeyLength());
            keyOwned = Arrays.clone(((KeyParameter) param.getParameters()).getKey());
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.GCM_INVALID_PARAMETER));
        }


        if (nonceOwned.length < 12)
        {
            PacketCipherException.from(
                    new IllegalArgumentException(ExceptionMessages.GCM_IV_TOO_SHORT)
            );
        }

        //
        // Assert input and output make sense with respect to mac bytes direction
        //

        int remaining = encryption ? len : len - macSizeBytes;
        final long totalLen = remaining;
        final int outputLen = encryption ? len + macSizeBytes : len - macSizeBytes;

        PacketCipherChecks.checkInputAndOutputAEAD(encryption,input,inOff,len,output,outOff,macSizeBytes);

        final byte[] s = AESPacketCipher.createS(true);
        final int[][] workingKey = AESPacketCipher.generateWorkingKey(true, keyOwned);

        // Create H, init multiplier
        final byte[] H = new byte[blockSize];
        AESPacketCipher.processBlock(true, workingKey, s, H, 0, H, 0);
        initMultiplier(mulT, H);


        final byte[] J0 = new byte[blockSize];
        if (nonceOwned.length == 12)
        {
            System.arraycopy(nonceOwned, 0, J0, 0, nonceOwned.length);
            J0[J0.length - 1] = 0x01;
        }
        else
        {
            gHASH(J0, nonceOwned, nonceOwned.length, mulT);
            byte[] X = new byte[blockSize];
            Pack.longToBigEndian((long) nonceOwned.length * 8, X, 8);
            gHASHBlock(J0, X, mulT);
        }

        final byte[] S = new byte[blockSize];
        final long adLen;

        // Inject ad into hash
        if (ad != null)
        {
            adLen = ad.length;
            int l = ad.length;
            int offset = 0;
            while (l > S.length)
            {
                gHASHBlock(S, ad, offset, mulT);
                offset += S.length;
                l -= S.length;
            }
            gHASHPartial(S, ad, offset, l, mulT);
        }
        else
        {
            adLen = 0;
        }

        final byte[] counter = Arrays.clone(J0);
        int blocksRemaining = -2;


        final byte[] ctrBlock = new byte[blockSize];
        while (remaining > blockSize)
        {
            blocksRemaining = assertBlocksRemaining(blocksRemaining);

            getNextCtrBlock(counter); // Step counter

            AESPacketCipher.processBlock(
                    true,
                    workingKey,
                    s,
                    counter,
                    0,
                    ctrBlock, 0); // make key stream

            GCMUtil.xor(ctrBlock, input, inOff);
            if (encryption)
            {
                gHASHBlock(S, ctrBlock, mulT);
            }
            else
            {
                gHASHBlock(S, input, inOff, mulT);
            }

            System.arraycopy(ctrBlock, 0, output, outOff, blockSize);


            remaining -= blockSize;
            outOff += blockSize;
            inOff += blockSize;
        }


        // Finish up encryption.
        assertBlocksRemaining(blocksRemaining);
        getNextCtrBlock(counter); // Step counter
        AESPacketCipher.processBlock(
                true,
                workingKey,
                s,
                counter,
                0,
                ctrBlock, 0); // make key stream


        if (encryption)
        {
            GCMUtil.xor(ctrBlock, 0, input, inOff, remaining);
            gHASHPartial(S, ctrBlock, 0, remaining, mulT);
        }
        else
        {
            gHASHPartial(S, input, inOff, remaining, mulT);
            GCMUtil.xor(ctrBlock, 0, input, inOff, remaining);
        }

        inOff += remaining;

        System.arraycopy(ctrBlock, 0, output, outOff, remaining);


        outOff += remaining;

        byte[] X = new byte[blockSize];
        Pack.longToBigEndian(adLen * 8, X, 0);
        Pack.longToBigEndian(totalLen * 8, X, 8);

        gHASHBlock(S, X, mulT);


        byte[] tag = new byte[blockSize];
        AESPacketCipher.processBlock(true, workingKey, s, J0, 0, tag, 0);
        GCMUtil.xor(tag, S);

        if (encryption)
        {
            // Copy tag to output
            System.arraycopy(tag, 0, output, outOff, macSizeBytes);
        }
        else
        {
            if (!Arrays.constantTimeAreEqual(macSizeBytes, tag, 0, input, inOff))
            {
                Arrays.clear(output, outOffStart, (int) totalLen);
                throw PacketCipherException.from(new InvalidCipherTextException("mac check in GCM failed"));
            }
        }

        Arrays.clear(nonceOwned);
        Arrays.clear(S);
        Arrays.clear(J0);
        Arrays.clear(X);
        Arrays.clear(H);
        Arrays.clear(mulT);
        Arrays.clear(workingKey);
        Arrays.clear(keyOwned);

        return outputLen;
    }


    private int assertBlocksRemaining(int blocksRemaining) throws PacketCipherException
    {
        if (blocksRemaining == 0)
        {
            throw PacketCipherException.from(new IllegalStateException("Attempt to process too many blocks"));
        }
        blocksRemaining--;
        return blocksRemaining;
    }


    /**
     * This method does not assert blocks remaining, this must
     * be checked externally!
     *
     * @param counter
     */
    private static void getNextCtrBlock(byte[] counter)
    {
        int c = 1;
        c += counter[15] & 0xFF;
        counter[15] = (byte) c;
        c >>>= 8;
        c += counter[14] & 0xFF;
        counter[14] = (byte) c;
        c >>>= 8;
        c += counter[13] & 0xFF;
        counter[13] = (byte) c;
        c >>>= 8;
        c += counter[12] & 0xFF;
        counter[12] = (byte) c;
    }

    private static void gHASH(byte[] Y, byte[] b, int len, long[][] T)
    {
        for (int pos = 0; pos < len; pos += AESPacketCipher.BLOCK_SIZE)
        {
            int num = Math.min(len - pos, AESPacketCipher.BLOCK_SIZE);
            gHASHPartial(Y, b, pos, num, T);
        }
    }


    private static void gHASHBlock(byte[] Y, byte[] b, long[][] T)
    {
        GCMUtil.xor(Y, b);
        multiplyH(Y, T);
    }

    private static void gHASHBlock(byte[] Y, byte[] b, int off, long[][] T)
    {
        GCMUtil.xor(Y, b, off);
        multiplyH(Y, T);
    }

    private static void gHASHPartial(byte[] Y, byte[] b, int off, int len, long[][] T)
    {
        GCMUtil.xor(Y, b, off, len);
        multiplyH(Y, T);
    }


    private static void multiplyH(byte[] x, long[][] T)
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


    protected static void initMultiplier(long[][] t, byte[] h)
    {
        // T[1] = H.p^7
        GCMUtil.asLongs(h, t[1]);
        GCMUtil.multiplyP7(t[1], t[1]);
        for (int n = 2; n < 256; n += 2)
        {
            // T[2.n] = T[n].p^-1
            GCMUtil.divideP(t[n >> 1], t[n]);
            // T[2.n + 1] = T[2.n] + T[1]
            GCMUtil.xor(t[n], t[1], t[n + 1]);
        }
    }

    @Override
    public String toString()
    {
        return "GCM-PS[Java](AES[Java])";
    }

    @Override
    public void destroy()
            throws DestroyFailedException
    {
        destroyed = true;
    }

    @Override
    public boolean isDestroyed()
    {
        return destroyed;
    }
}
