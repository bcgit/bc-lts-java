package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public class AESGCMSIVPacketCipher
    extends PacketCipherEngine
{
    public static AESGCMSIVPacketCipher newInstance()
    {
        return new AESGCMSIVPacketCipher();
    }

    private AESGCMSIVPacketCipher()
    {

    }


    /**
     * The nonce length.
     */
    private static final int NONCELEN = 12;


    /**
     * The initialisation flag.
     */
    private static final int INIT = 1;

    /**
     * The aeadComplete flag.
     */
    private static final int AEAD_COMPLETE = 2;
    /**
     * The buffer length.
     */
    private static final int BUFLEN = 16;
    /**
     * The halfBuffer length.
     */
    private static final int HALFBUFLEN = BUFLEN >> 1;
    /**
     * The maximum data length (AEAD/PlainText). Due to implementation constraints this is restricted to the maximum
     * array length (https://programming.guide/java/array-maximum-length.html) minus the BUFLEN to allow for the MAC
     */
    private static final int MAX_DATALEN = Integer.MAX_VALUE - 8 - BUFLEN;
    /**
     * The top bit mask.
     */
    private static final byte MASK = (byte)0x80;
    /**
     * The addition constant.
     */
    private static final byte ADD = (byte)0xE1;

    @Override
    public int getOutputSize(boolean encryption, CipherParameters parameters, int len)
    {
        return 0;
    }

    @Override
    public int processPacket(boolean encryption, CipherParameters parameters, byte[] input, int inOff, int len, byte[] output, int outOff)
        throws PacketCipherException
    {

        final BlockCipher theCipher;
        final GCMMultiplier theMultiplier;
        final byte[] theGHash = new byte[BUFLEN];
        final byte[] theReverse = new byte[BUFLEN];
        final GCMSIVHasher theAEADHasher;
        final GCMSIVHasher theDataHasher;
        GCMSIVCache thePlain = null;
        GCMSIVCache theEncData;
        boolean forEncryption;
        byte[] theInitialAEAD;
        byte[] theNonce;
        int theFlags = 0;

        // defined fixed
        byte[] macBlock = new byte[BLOCK_SIZE];
        long[][] T = null;

        //init
        /* Set defaults */
        /* Store parameters */
        theCipher = new AESEngine();
        theMultiplier = new Tables4kGCMMultiplier();

        /* Create the hashers */
        theAEADHasher = new GCMSIVHasher();
        theDataHasher = new GCMSIVHasher();
        byte[] myInitialAEAD = null;
        byte[] myNonce = null;
        KeyParameter myKey = null;

        /* Access parameters */
        if (parameters instanceof AEADParameters)
        {
            final AEADParameters myAEAD = (AEADParameters)parameters;
            myInitialAEAD = myAEAD.getAssociatedText();
            myNonce = myAEAD.getNonce();
            myKey = myAEAD.getKey();
        }
        else if (parameters instanceof ParametersWithIV)
        {
            final ParametersWithIV myParms = (ParametersWithIV)parameters;
            myNonce = myParms.getIV();
            myKey = (KeyParameter)myParms.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
        }

        /* Check nonceSize */
        if (myNonce == null || myNonce.length != NONCELEN)
        {
            throw new IllegalArgumentException("Invalid nonce");
        }

        /* Check keysize */
        if (myKey == null
            || (myKey.getKeyLength() != BUFLEN
            && myKey.getKeyLength() != (BUFLEN << 1)))
        {
            throw new IllegalArgumentException("Invalid key");
        }

        /* Reset details */
        forEncryption = encryption;
        theInitialAEAD = myInitialAEAD;
        theNonce = myNonce;

        /* Initialise the keys */
        //deriveKeys(myKey);
        final byte[] myIn = new byte[BUFLEN];
        final byte[] myOut = new byte[BUFLEN];
        final byte[] myResult = new byte[BUFLEN];
        final byte[] myEncKey = new byte[myKey.getKeyLength()];

        /* Prepare for encryption */
        System.arraycopy(theNonce, 0, myIn, BUFLEN - NONCELEN, NONCELEN);
        theCipher.init(true, myKey);

        /* Derive authentication key */
        int myOff = 0;
        theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myResult, myOff, HALFBUFLEN);
        myIn[0]++;
        myOff += HALFBUFLEN;
        theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myResult, myOff, HALFBUFLEN);

        /* Derive encryption key */
        myIn[0]++;
        myOff = 0;
        theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
        myIn[0]++;
        myOff += HALFBUFLEN;
        theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);

        /* If we have a 32byte key */
        if (myEncKey.length == BUFLEN << 1)
        {
            /* Derive remainder of encryption key */
            myIn[0]++;
            myOff += HALFBUFLEN;
            theCipher.processBlock(myIn, 0, myOut, 0);
            System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
            myIn[0]++;
            myOff += HALFBUFLEN;
            theCipher.processBlock(myIn, 0, myOut, 0);
            System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
        }

        /* Initialise the Cipher */
        theCipher.init(true, new KeyParameter(myEncKey));

        /* Initialise the multiplier */
        fillReverse(myResult, 0, BUFLEN, myOut);
        mulX(myOut);
        theMultiplier.init(myOut);
        theFlags |= INIT;
        //resetStreams();
        if (thePlain != null)
        {
            thePlain.clearBuffer();
        }

        /* Reset hashers */
        theAEADHasher.reset();
        theDataHasher.reset();

        /* Recreate streams (to release memory) */
        thePlain = new GCMSIVCache();
        theEncData = forEncryption ? null : new GCMSIVCache();

        /* Initialise AEAD if required */
        theFlags &= ~AEAD_COMPLETE;
        Arrays.fill(theGHash, (byte)0);
        if (theInitialAEAD != null)
        {
            theAEADHasher.updateHash(theInitialAEAD, 0, theInitialAEAD.length, theReverse, theGHash, T);
        }

        //processBytes
        /* Check that we have initialised */
        theFlags = checkStatus(len, theFlags, encryption, theAEADHasher, thePlain, theEncData, theReverse, theGHash, T);

        /* Check input buffer */
        checkBuffer(input, inOff, len, false);

        /* Store the data */
        if (forEncryption)
        {
            thePlain.write(input, inOff, len);
            theDataHasher.updateHash(input, inOff, len, theReverse, theGHash, T);
        }
        else
        {
            theEncData.write(input, inOff, len);
        }

        //doFinal

        /* Check that we have initialised */
        theFlags = checkStatus(0, theFlags, encryption, theAEADHasher, thePlain, theEncData, theReverse, theGHash, T);

        /* Check output buffer */
        checkBuffer(output, outOff, getOutputSize(forEncryption, thePlain, theEncData, 0), true);

        /* If we are encrypting */
        if (forEncryption)
        {
            /* Derive the tag */
            final byte[] myTag = calculateTag(theCipher, theDataHasher, theAEADHasher, theReverse, theGHash, T, theNonce);

            /* encrypt the plain text */
            final int myDataLen = BUFLEN + encryptPlain(theCipher, thePlain, myTag, output, outOff);

            /* Add the tag to the output */
            System.arraycopy(myTag, 0, output, outOff + thePlain.size(), BUFLEN);

            System.arraycopy(myTag, 0, macBlock, 0, macBlock.length);

            /* Reset the streams */
            //resetStreams();
            return myDataLen;

            /* else we are decrypting */
        }
        else
        {
            try
            {
                /* decrypt to plain text */
                decryptPlain(theCipher, theDataHasher, theAEADHasher, theEncData,
                    thePlain, theNonce, macBlock, theReverse, theGHash, T);
            }
            catch (InvalidCipherTextException e)
            {
                throw PacketCipherException.from(e);
            }


            /* Release plain text */
            final int myDataLen = thePlain.size();
            final byte[] mySrc = thePlain.getBuffer();
            System.arraycopy(mySrc, 0, output, outOff, myDataLen);

            /* Reset the streams */
            //resetStreams();
            return myDataLen;
        }
    }

    private int checkStatus(final int pLen, int theFlags, boolean forEncryption, GCMSIVHasher theAEADHasher,
                            GCMSIVCache thePlain, GCMSIVCache theEncData, byte[] theReverse, byte[] theGHash, long[][] T)
    {
        /* Check we are initialised */
        if ((theFlags & INIT) == 0)
        {
            throw new IllegalStateException("Cipher is not initialised");
        }

        /* Complete the AEAD section if this is the first data */
        if ((theFlags & AEAD_COMPLETE) == 0)
        {
            theAEADHasher.completeHash(theReverse, theGHash, T);
            theFlags |= AEAD_COMPLETE;
        }

        /* Make sure that we haven't breached data limit */
        long dataLimit = MAX_DATALEN;
        long currBytes = thePlain.size();
        if (!forEncryption)
        {
            dataLimit += BUFLEN;
            currBytes = theEncData.size();
        }
        if (currBytes + Long.MIN_VALUE
            > (dataLimit - pLen) + Long.MIN_VALUE)
        {
            throw new IllegalStateException("byte count exceeded");
        }
        return theFlags;
    }

    /**
     * calculate tag.
     *
     * @return the calculated tag
     */
    private byte[] calculateTag(BlockCipher theCipher, GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, byte[] theReverse,
                                byte[] theGHash, long[][] T, byte[] theNonce)
    {
        /* Complete the hash */
        theDataHasher.completeHash(theReverse, theGHash, T);
        final byte[] myPolyVal = completePolyVal(theDataHasher, theAEADHasher, theGHash, T);

        /* calculate polyVal */
        final byte[] myResult = new byte[BUFLEN];

        /* Fold in the nonce */
        for (int i = 0; i < NONCELEN; i++)
        {
            myPolyVal[i] ^= theNonce[i];
        }

        /* Clear top bit */
        myPolyVal[BUFLEN - 1] &= (MASK - 1);

        /* Calculate tag and return it */
        theCipher.processBlock(myPolyVal, 0, myResult, 0);
        return myResult;
    }

    /**
     * complete polyVAL.
     *
     * @return the calculated value
     */
    private byte[] completePolyVal(GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, byte[] theGHash, long[][] T)
    {
        /* Build the polyVal result */
        final byte[] myResult = new byte[BUFLEN];
        //gHashLengths();
        /* Create reversed bigEndian buffer to keep it simple */
        final byte[] myIn = new byte[BUFLEN];
        Pack.longToBigEndian(Bytes.SIZE * theDataHasher.getBytesProcessed(), myIn, 0);
        Pack.longToBigEndian(Bytes.SIZE * theAEADHasher.getBytesProcessed(), myIn, Longs.BYTES);

        /* hash value */
        gHASH(myIn, theGHash, T);
        fillReverse(theGHash, 0, BUFLEN, myResult);
        return myResult;
    }

    /**
     * Check buffer.
     *
     * @param pBuffer the buffer
     * @param pOffset the offset
     * @param pLen    the length
     * @param pOutput is this an output buffer?
     */
    private static void checkBuffer(final byte[] pBuffer,
                                    final int pOffset,
                                    final int pLen,
                                    final boolean pOutput)
    {
        /* Access lengths */
        final int myBufLen = pBuffer == null ? 0 : pBuffer.length;
        final int myLast = pOffset + pLen;

        /* Check for negative values and buffer overflow */
        final boolean badLen = pLen < 0 || pOffset < 0 || myLast < 0;
        if (badLen || myLast > myBufLen)
        {
            throw pOutput
                ? new OutputLengthException("Output buffer too short.")
                : new DataLengthException("Input buffer too short.");
        }
    }

    /**
     * encrypt data stream.
     *
     * @param pCounter the counter
     * @param pTarget  the target buffer
     * @param pOffset  the target offset
     * @return the length of data encrypted
     */
    private int encryptPlain(BlockCipher theCipher, GCMSIVCache thePlain, final byte[] pCounter,
                             final byte[] pTarget,
                             final int pOffset)
    {
        /* Access buffer and length */
        final byte[] mySrc = thePlain.getBuffer();
        final byte[] myCounter = Arrays.clone(pCounter);
        myCounter[BUFLEN - 1] |= MASK;
        final byte[] myMask = new byte[BUFLEN];
        int myRemaining = thePlain.size();
        int myOff = 0;

        /* While we have data to process */
        while (myRemaining > 0)
        {
            /* Generate the next mask */
            theCipher.processBlock(myCounter, 0, myMask, 0);

            /* Xor data into mask */
            final int myLen = Math.min(BUFLEN, myRemaining);
            xorBlock(myMask, mySrc, myOff, myLen);

            /* Copy encrypted data to output */
            System.arraycopy(myMask, 0, pTarget, pOffset + myOff, myLen);

            /* Adjust counters */
            myRemaining -= myLen;
            myOff += myLen;
            incrementCounter(myCounter);
        }

        /* Return the amount of data processed */
        return thePlain.size();
    }

    private class GCMSIVHasher
    {
        /**
         * Cache.
         */
        private final byte[] theBuffer = new byte[BUFLEN];

        /**
         * Single byte cache.
         */
        private final byte[] theByte = new byte[1];

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
         * Reset the hasher.
         */
        void reset()
        {
            numActive = 0;
            numHashed = 0;
        }

        /**
         * update hash.
         *
         * @param pByte the byte
         */
        void updateHash(final byte pByte, byte[] theReverse, byte[] theGHash, long[][] T)
        {
            theByte[0] = pByte;
            updateHash(theByte, 0, 1, theReverse, theGHash, T);
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
            final int mySpace = BUFLEN - numActive;
            int numProcessed = 0;
            int myRemaining = pLen;
            if (numActive > 0
                && pLen >= mySpace)
            {
                /* Copy data into the cache and hash it */
                System.arraycopy(pBuffer, pOffset, theBuffer, numActive, mySpace);
                fillReverse(theBuffer, 0, BUFLEN, theReverse);
                gHASH(theReverse, theGHash, T);

                /* Adjust counters */
                numProcessed += mySpace;
                myRemaining -= mySpace;
                numActive = 0;
            }

            /* While we have full blocks */
            while (myRemaining >= BUFLEN)
            {
                /* Access the next data */
                fillReverse(pBuffer, pOffset + numProcessed, BUFLEN, theReverse);
                gHASH(theReverse, theGHash, T);

                /* Adjust counters */
                numProcessed += BUFLEN;
                myRemaining -= BUFLEN;
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
                Arrays.fill(theReverse, (byte)0);
                fillReverse(theBuffer, 0, numActive, theReverse);

                /* hash value */
                gHASH(theReverse, theGHash, T);
            }
        }
    }

    private static class GCMSIVCache
        extends ByteArrayOutputStream
    {
        /**
         * Constructor.
         */
        GCMSIVCache()
        {
        }

        /**
         * Obtain the buffer.
         *
         * @return the buffer
         */
        byte[] getBuffer()
        {
            return this.buf;
        }

        /**
         * Clear the buffer.
         */
        void clearBuffer()
        {
            Arrays.fill(getBuffer(), (byte)0);
        }
    }

    private static void fillReverse(final byte[] pInput,
                                    final int pOffset,
                                    final int pLength,
                                    final byte[] pOutput)
    {
        /* Loop through the buffer */
        for (int i = 0, j = BUFLEN - 1; i < pLength; i++, j--)
        {
            /* Copy byte */
            pOutput[j] = pInput[pOffset + i];
        }
    }

    private void gHASH(final byte[] pNext, byte[] theGHash, long[][] T)
    {
        xorBlock(theGHash, pNext);
        multiplyH(theGHash, T);
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
        for (int i = 0; i < BUFLEN; i++)
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

    /**
     * multiply by X.
     *
     * @param pValue the value to adjust
     */
    private static void mulX(final byte[] pValue)
    {
        /* Loop through the bytes */
        byte myMask = (byte)0;
        for (int i = 0; i < BUFLEN; i++)
        {
            final byte myValue = pValue[i];
            pValue[i] = (byte)(((myValue >> 1) & ~MASK) | myMask);
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
     *
     * @throws InvalidCipherTextException on data too short or mac check failed
     */
    private void decryptPlain(BlockCipher theCipher, GCMSIVHasher theDataHasher, GCMSIVHasher theAEADHasher, GCMSIVCache theEncData,
                              GCMSIVCache thePlain, byte[] theNonce, byte[] macBlock, byte[] theReverse, byte[] theGHash, long[][] T)
        throws InvalidCipherTextException
    {
        /* Access buffer and length */
        final byte[] mySrc = theEncData.getBuffer();
        int myRemaining = theEncData.size() - BUFLEN;

        /* Check for insufficient data */
        if (myRemaining < 0)
        {
            throw new InvalidCipherTextException("Data too short");
        }

        /* Access counter */
        final byte[] myExpected = Arrays.copyOfRange(mySrc, myRemaining, myRemaining + BUFLEN);
        final byte[] myCounter = Arrays.clone(myExpected);
        myCounter[BUFLEN - 1] |= MASK;
        final byte[] myMask = new byte[BUFLEN];
        int myOff = 0;

        /* While we have data to process */
        while (myRemaining > 0)
        {
            /* Generate the next mask */
            theCipher.processBlock(myCounter, 0, myMask, 0);

            /* Xor data into mask */
            final int myLen = Math.min(BUFLEN, myRemaining);
            xorBlock(myMask, mySrc, myOff, myLen);

            /* Write data to plain dataStream */
            thePlain.write(myMask, 0, myLen);
            theDataHasher.updateHash(myMask, 0, myLen, theReverse, theGHash, T);

            /* Adjust counters */
            myRemaining -= myLen;
            myOff += myLen;
            incrementCounter(myCounter);
        }

        /* Derive and check the tag */
        final byte[] myTag = calculateTag(theCipher, theDataHasher, theAEADHasher, theReverse, theGHash, T, theNonce);
        if (!Arrays.constantTimeAreEqual(myTag, myExpected))
        {
            //reset();
            throw new InvalidCipherTextException("mac check failed");
        }

        System.arraycopy(myTag, 0, macBlock, 0, macBlock.length);
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

    private int getOutputSize(boolean forEncryption, GCMSIVCache thePlain, GCMSIVCache theEncData, final int pLen)
    {
        if (forEncryption)
        {
            return pLen + thePlain.size() + BUFLEN;
        }
        final int myCurr = pLen + theEncData.size();
        return myCurr > BUFLEN ? myCurr - BUFLEN : 0;
    }
}
