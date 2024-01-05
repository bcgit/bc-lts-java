package org.bouncycastle.crypto.modes;


import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESNativeGCMSIVPacketCipher;
import org.bouncycastle.crypto.engines.AESPacketCipher;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public class AESGCMSIVPacketCipher
        implements AESGCMSIVModePacketCipher
{

    public static AESGCMSIVModePacketCipher newInstance()
    {
        if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCMSIV_PC))
        {
            return new AESNativeGCMSIVPacketCipher();
        }
        return new AESGCMSIVPacketCipher();
    }

    public AESGCMSIVPacketCipher()
    {

    }


    /**
     * The halfBuffer length.
     */
    private static final int HALFBUFLEN = AESPacketCipher.BLOCK_SIZE >> 1;
    /**
     * The maximum data length (AEAD/PlainText). Due to implementation constraints this is restricted to the maximum
     * array length (https://programming.guide/java/array-maximum-length.html) minus the BUFLEN to allow for the MAC
     */
    private static final int MAX_DATALEN = Integer.MAX_VALUE - 8 - AESPacketCipher.BLOCK_SIZE;
    /**
     * The top bit mask.
     */
    private static final byte MASK = (byte) 0x80;
    /**
     * The addition constant.
     */
    private static final byte ADD = (byte) 0xE1;

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE);
        }

        final int macSize = AESPacketCipher.BLOCK_SIZE;

        if (encryption)
        {
            return PacketCipherChecks.addCheckInputOverflow(len, macSize);
        }
        else if (len < macSize)
        {
            throw new DataLengthException(ExceptionMessages.LEN_PARAMETER_INVALID);
        }

        checkParameters(parameters);
        return len - macSize;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
    throws PacketCipherException
    {
        PacketCipherChecks.checkBoundsInput(input, inOff, len, output, outOff); // Output len varies with direction
        PacketCipherChecks.checkInputAndOutputAEAD(encryption, input, inOff, len, output, outOff,
                AESPacketCipher.BLOCK_SIZE);

        final byte[] theGHash = new byte[AESPacketCipher.BLOCK_SIZE];
        final byte[] theReverse = new byte[AESPacketCipher.BLOCK_SIZE];
        final GCMSIVHasher theAEADHasher = new GCMSIVHasher();
        final GCMSIVHasher theDataHasher = new GCMSIVHasher();
        byte[] myInitialAEAD = null;
        byte[] myNonceOwned;
        byte[] myKeyOwned;
        int[][] workingKey;
        byte[] s;
        long[][] T = new long[256][2];
        final byte[] myResult = new byte[AESPacketCipher.BLOCK_SIZE];
        /* Access parameters */
        if (parameters instanceof AEADParameters)
        {
            final AEADParameters myAEAD = (AEADParameters) parameters;
            myInitialAEAD = myAEAD.getAssociatedText();
            myNonceOwned = myAEAD.getNonce();
            PacketCipherChecks.checkKeyLengthExclude192(myAEAD.getKey().getKeyLength());
            myKeyOwned = Arrays.clone(myAEAD.getKey().getKey());
        }
        else if (parameters instanceof ParametersWithIV)
        {
            final ParametersWithIV myParms = (ParametersWithIV) parameters;
            myNonceOwned = Arrays.clone(myParms.getIV());
            PacketCipherChecks.checkKeyLengthExclude192(((KeyParameter) myParms.getParameters()).getKeyLength());
            myKeyOwned = Arrays.clone(((KeyParameter) myParms.getParameters()).getKey());
        }
        else
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.GCM_SIV_INVALID_PARAMETER));
        }
        /* Check nonceSize */
        if (myNonceOwned == null || myNonceOwned.length != NONCELEN)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.GCM_SIV_IV_SIZE));
        }

        s = AESPacketCipher.createS(true);
        workingKey = AESPacketCipher.generateWorkingKey(true, myKeyOwned);

        final byte[] myEncKey = new byte[myKeyOwned.length];

        final int outputLen = encryption ? len + AESPacketCipher.BLOCK_SIZE : len - AESPacketCipher.BLOCK_SIZE;

        try
        {

            /* Prepare for encryption */
            System.arraycopy(myNonceOwned, 0, theGHash, AESPacketCipher.BLOCK_SIZE - NONCELEN, NONCELEN);

            /* Derive authentication key */
            deriveKey(workingKey, s, theGHash, theReverse, myResult, 0);

            /* Derive encryption key */
            theGHash[0]++;
            int myOff = deriveKey(workingKey, s, theGHash, theReverse, myEncKey, 0);

            /* If we have a 32byte key */
            if (myEncKey.length == 32)
            {
                /* Derive remainder of encryption key */
                theGHash[0]++;
                myOff += HALFBUFLEN;
                deriveKey(workingKey, s, theGHash, theReverse, myEncKey, myOff);
            }

            /* Initialise the Cipher */
            int keyLen = myEncKey.length;
            PacketCipherChecks.checkKeyLength(keyLen);

            Arrays.clear(workingKey);
            Arrays.clear(s);

            s = AESPacketCipher.createS(true);
            workingKey = AESPacketCipher.generateWorkingKey(true, myEncKey);

            /* Initialise the multiplier */
            fillReverse(myResult, 0, AESPacketCipher.BLOCK_SIZE, theReverse);
            mulX(theReverse);
            initMultiplier(T, theReverse);
            Arrays.fill(theGHash, (byte) 0);

            /* Initialise AEAD if required */
            if (myInitialAEAD != null)
            {
                theAEADHasher.updateHash(myInitialAEAD, 0, myInitialAEAD.length, theReverse, theGHash, T);
            }

            /* Complete the AEAD section if this is the first data */
            theAEADHasher.completeHash(theReverse, theGHash, T);
            /* Make sure that we haven't breached data limit */
            long dataLimit = MAX_DATALEN;
            if (!encryption)
            {
                dataLimit += AESPacketCipher.BLOCK_SIZE;
            }
            if ((long) len + Long.MIN_VALUE > (dataLimit - len) + Long.MIN_VALUE)
            {
                throw PacketCipherException.from(new IllegalStateException("byte count exceeded"));
            }


            /* If we are encrypting */
            if (encryption)
            {
                theDataHasher.updateHash(input, inOff, len, theReverse, theGHash, T);
                /* Derive the tag */
                final byte[] myTag = calculateTag(theDataHasher, theAEADHasher, theReverse, theGHash, T, myNonceOwned,
                        workingKey, s);
                /* encrypt the plain text */
                encryptPlain(input, inOff, len, myTag, output, outOff, workingKey, s);
                /* Add the tag to the output */
                System.arraycopy(myTag, 0, output, outOff + len, AESPacketCipher.BLOCK_SIZE);
            }
            else
            {
                /* decrypt to plain text */
                decryptPlain(theDataHasher, theAEADHasher, input, inOff, len,
                        output, outOff, myNonceOwned, theReverse, theGHash, T, workingKey, s);
            }

        }
        catch (Throwable t)
        {
            // Offset with respect to array length has been asserted by this point.
            Arrays.clear(output, outOff, Math.min(output.length - outOff, outputLen));
            throw PacketCipherException.from(t);
        }
        finally
        {


            for (int[] ints : workingKey)
            {
                Arrays.fill(ints, 0);
            }
            Arrays.clear(theGHash);
            Arrays.clear(theReverse);
            Arrays.clear(myNonceOwned);
            Arrays.clear(myKeyOwned);
            Arrays.clear(workingKey);
            Arrays.clear(s);
        }

        return outputLen;
    }

    private static int deriveKey(int[][] workingKey, byte[] s, byte[] myIn, byte[] myOut, byte[] myEncKey,
                                 int myOff)
    {

        AESPacketCipher.processBlock(true, workingKey, s, myIn, 0, myOut, 0);
        //encryptBlock(myIn, 0, myOut, 0, workingKey, s, workingKey.length-1);
        System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
        myIn[0]++;
        myOff += HALFBUFLEN;

        AESPacketCipher.processBlock(true, workingKey, s, myIn, 0, myOut, 0);

        //encryptBlock(myIn, 0, myOut, 0, workingKey, s, workingKey.length-1);
        System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
        return myOff;
    }

    /**
     * calculate tag.
     *
     * @return the calculated tag
     */
    private static byte[] calculateTag(GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, byte[] theReverse,
                                       byte[] theGHash, long[][] T, byte[] theNonce, int[][] workingKey, byte[] s)
    {
        /* Complete the hash */
        theDataHasher.completeHash(theReverse, theGHash, T);
        final byte[] myPolyVal = completePolyVal(theDataHasher, theAEADHasher, theGHash, T);

        /* calculate polyVal */
        final byte[] myResult = new byte[AESPacketCipher.BLOCK_SIZE];

        /* Fold in the nonce */
        for (int i = 0; i < NONCELEN; i++)
        {
            myPolyVal[i] ^= theNonce[i];
        }

        /* Clear top bit */
        myPolyVal[AESPacketCipher.BLOCK_SIZE - 1] &= (MASK - 1);

        /* Calculate tag and return it */

        AESPacketCipher.processBlock(true, workingKey, s, myPolyVal, 0, myResult, 0);
        // encryptBlock(myPolyVal, 0, myResult, 0, workingKey, s, ROUNDS);
        //theCipher.processBlock(myPolyVal, 0, myResult, 0);
        return myResult;
    }

    /**
     * complete polyVAL.
     *
     * @return the calculated value
     */
    private static byte[] completePolyVal(GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, byte[] theGHash,
                                          long[][] T)
    {
        /* Build the polyVal result */
        final byte[] myResult = new byte[AESPacketCipher.BLOCK_SIZE];
        /* Create reversed bigEndian buffer to keep it simple */
        final byte[] myIn = new byte[AESPacketCipher.BLOCK_SIZE];
        Pack.longToBigEndian(Bytes.SIZE * theDataHasher.getBytesProcessed(), myIn, 0);
        Pack.longToBigEndian(Bytes.SIZE * theAEADHasher.getBytesProcessed(), myIn, Longs.BYTES);

        /* hash value */
        gHASH(myIn, theGHash, T);
        fillReverse(theGHash, 0, AESPacketCipher.BLOCK_SIZE, myResult);
        return myResult;
    }


    /**
     * encrypt data stream.
     *
     * @param pCounter the counter
     * @param pTarget  the target buffer
     * @param pOffset  the target offset
     * @return the length of data encrypted
     */
    private static int encryptPlain(byte[] input, int inOff, int len, final byte[] pCounter, final byte[] pTarget,
                                    int pOffset, int[][] workingKey, byte[] s)
    {
        /* Access buffer and length */
        final byte[] myCounter = Arrays.clone(pCounter);
        myCounter[AESPacketCipher.BLOCK_SIZE - 1] |= MASK;
        final byte[] myMask = new byte[AESPacketCipher.BLOCK_SIZE];
        int myRemaining = len;
        /* While we have data to process */
        while (myRemaining > 0)
        {
            /* Generate the next mask */
            AESPacketCipher.processBlock(true, workingKey, s, myCounter, 0, myMask, 0);
//            encryptBlock(myCounter, 0, myMask, 0, workingKey, s, ROUNDS);
            /* Xor data into mask */
            final int myLen = Math.min(AESPacketCipher.BLOCK_SIZE, myRemaining);
            xorBlock(myMask, input, inOff, myLen);
            /* Copy encrypted data to output */
            System.arraycopy(myMask, 0, pTarget, pOffset, myLen);
            /* Adjust counters */
            myRemaining -= myLen;
            inOff += myLen;
            pOffset += myLen;
            incrementCounter(myCounter);
        }

        /* Return the amount of data processed */
        return len;
    }

    private static class GCMSIVHasher
    {
        /**
         * Cache.
         */
        private final byte[] theBuffer = new byte[AESPacketCipher.BLOCK_SIZE];

        /**
         * Count of active bytes in cache.
         */
        private int numActive;

        /**
         * Count of hashed bytes.
         */
        private long numHashed;

        /**
         * Obtain the count of bytes hashed.
         *
         * @return the count
         */
        long getBytesProcessed()
        {
            return numHashed;
        }

        /**
         * update hash.
         *
         * @param pBuffer the buffer
         * @param pOffset the offset within the buffer
         * @param pLen    the length of data
         */
        void updateHash(final byte[] pBuffer,
                        final int pOffset,
                        final int pLen, byte[] theReverse, byte[] theGHash, long[][] T)
        {
            /* If we should process the cache */
            final int mySpace = AESPacketCipher.BLOCK_SIZE - numActive;
            int numProcessed = 0;
            int myRemaining = pLen;
            if (numActive > 0 && pLen >= mySpace)
            {
                /* Copy data into the cache and hash it */
                System.arraycopy(pBuffer, pOffset, theBuffer, numActive, mySpace);
                fillReverse(theBuffer, 0, AESPacketCipher.BLOCK_SIZE, theReverse);
                gHASH(theReverse, theGHash, T);

                /* Adjust counters */
                numProcessed += mySpace;
                myRemaining -= mySpace;
                numActive = 0;
            }

            /* While we have full blocks */
            while (myRemaining >= AESPacketCipher.BLOCK_SIZE)
            {
                /* Access the next data */
                fillReverse(pBuffer, pOffset + numProcessed, AESPacketCipher.BLOCK_SIZE, theReverse);
                gHASH(theReverse, theGHash, T);

                /* Adjust counters */
                numProcessed += AESPacketCipher.BLOCK_SIZE;
                myRemaining -= AESPacketCipher.BLOCK_SIZE;
            }

            /* If we have remaining data */
            if (myRemaining > 0)
            {
                /* Copy data into the cache */
                System.arraycopy(pBuffer, pOffset + numProcessed, theBuffer, numActive, myRemaining);
                numActive += myRemaining;
            }

            /* Adjust the number of bytes processed */
            numHashed += pLen;
        }

        /**
         * complete hash.
         */
        void completeHash(byte[] theReverse, byte[] theGHash, long[][] T)
        {
            /* If we have remaining data */
            if (numActive > 0)
            {
                /* Access the next data */
                Arrays.fill(theReverse, (byte) 0);
                fillReverse(theBuffer, 0, numActive, theReverse);
                /* hash value */
                gHASH(theReverse, theGHash, T);
            }
        }
    }

    private static void fillReverse(final byte[] pInput,
                                    final int pOffset,
                                    final int pLength,
                                    final byte[] pOutput)
    {
        /* Loop through the buffer */
        for (int i = 0, j = AESPacketCipher.BLOCK_SIZE - 1; i < pLength; i++, j--)
        {
            /* Copy byte */
            pOutput[j] = pInput[pOffset + i];
        }
    }

    private static void gHASH(final byte[] pNext, byte[] theGHash, long[][] T)
    {
        xorBlock(theGHash, pNext);
        mulH(theGHash, T);
    }

    protected static void mulH(byte[] x, long[][] T)
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


    /**
     * xor a full block buffer.
     *
     * @param pLeft  the left operand and result
     * @param pRight the right operand
     */
    private static void xorBlock(final byte[] pLeft,
                                 final byte[] pRight)
    {
        /* Loop through the bytes */
        for (int i = 0; i < AESPacketCipher.BLOCK_SIZE; i++)
        {
            pLeft[i] ^= pRight[i];
        }
    }

    /**
     * xor a partial block buffer.
     *
     * @param pLeft   the left operand and result
     * @param pRight  the right operand
     * @param pOffset the offset in the right operand
     * @param pLength the length of data in the right operand
     */
    private static void xorBlock(final byte[] pLeft,
                                 final byte[] pRight,
                                 final int pOffset,
                                 final int pLength)
    {
        /* Loop through the bytes */
        for (int i = 0; i < pLength; i++)
        {
            pLeft[i] ^= pRight[i + pOffset];
        }
    }

    /**
     * multiply by X.
     *
     * @param pValue the value to adjust
     */
    private static void mulX(final byte[] pValue)
    {
        /* Loop through the bytes */
        byte myMask = (byte) 0;
        for (int i = 0; i < AESPacketCipher.BLOCK_SIZE; i++)
        {
            final byte myValue = pValue[i];
            pValue[i] = (byte) (((myValue >> 1) & ~MASK) | myMask);
            myMask = (myValue & 1) == 0 ? 0 : MASK;
        }

        /* Xor in addition if last bit was set */
        if (myMask != 0)
        {
            pValue[0] ^= ADD;
        }
    }

    /**
     * decrypt data stream.
     */
    private static void decryptPlain(GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, byte[] input, int inOff,
                                     int len,
                                     byte[] output, int outOff, byte[] theNonce, byte[] theReverse, byte[] theGHash,
                                     long[][] T, int[][] workingKey, byte[] s)
    throws PacketCipherException
    {
        int myRemaining = len - AESPacketCipher.BLOCK_SIZE;
        /* Access counter */
        final byte[] myExpected = Arrays.copyOfRange(input, myRemaining + inOff,
                myRemaining + inOff + AESPacketCipher.BLOCK_SIZE);
        final byte[] myCounter = Arrays.clone(myExpected);
        myCounter[AESPacketCipher.BLOCK_SIZE - 1] |= MASK;
        final byte[] myMask = new byte[AESPacketCipher.BLOCK_SIZE];
        int myOff = inOff;

        /* While we have data to process */
        while (myRemaining > 0)
        {
            /* Generate the next mask */
            AESPacketCipher.processBlock(true, workingKey, s, myCounter, 0, myMask, 0);
            /// encryptBlock(myCounter, 0, myMask, 0, workingKey, s, ROUNDS);

            /* Xor data into mask */
            final int myLen = Math.min(AESPacketCipher.BLOCK_SIZE, myRemaining);
            xorBlock(myMask, input, myOff, myLen);

            /* Write data to plain dataStream */
            System.arraycopy(myMask, 0, output, outOff, myLen);
            theDataHasher.updateHash(myMask, 0, myLen, theReverse, theGHash, T);

            /* Adjust counters */
            myRemaining -= myLen;
            myOff += myLen;
            outOff += myLen;
            incrementCounter(myCounter);
        }

        /* Derive and check the tag */
        final byte[] myTag = calculateTag(theDataHasher, theAEADHasher, theReverse, theGHash, T, theNonce, workingKey
                , s);
        if (!Arrays.constantTimeAreEqual(myTag, myExpected))
        {
            throw PacketCipherException.from(new InvalidCipherTextException("mac check failed"));
        }
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


    /**
     * increment the counter.
     *
     * @param pCounter the counter to increment
     */
    private static void incrementCounter(final byte[] pCounter)
    {
        /* Loop through the bytes incrementing counter */
        for (int i = 0; i < Integers.BYTES; i++)
        {
            if (++pCounter[i] != 0)
            {
                break;
            }
        }
    }

    @Override
    public String toString()
    {
        return "GCMSIV-PS[Java](AES[Java])";
    }
}
