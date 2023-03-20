package org.bouncycastle.crypto.paddings;


import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/**
 * A wrapper class that allows multi-block ciphers to be used to process data in
 * a piecemeal fashion with padding. The PaddedBufferedMultiBlockCipher
 * outputs a block only when the buffer is full and more data is being added,
 * or on a doFinal (unless the current block in the buffer is a pad block).
 * The default padding mechanism used is the one outlined in PKCS5/PKCS7.
 */
public class PaddedBufferedMultiBlockCipher
        extends DefaultBufferedMultiBlockCipher
{

    BlockCipherPadding padding;

    /**
     * Create a buffered block cipher with the desired padding.
     *
     * @param cipher  the underlying block cipher this buffering object wraps.
     * @param padding the padding type.
     */
    public PaddedBufferedMultiBlockCipher(
            MultiBlockCipher cipher,
            BlockCipherPadding padding)
    {
        super(cipher);
        this.padding = padding;
    }

    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     *                      encryption, if false for decryption.
     * @param params        the key and other data required by the cipher.
     * @throws IllegalArgumentException if the params argument is
     *                                  inappropriate.
     */
    public void init(
            boolean forEncryption,
            CipherParameters params)
            throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        reset();

        if (params instanceof ParametersWithRandom)
        {
            ParametersWithRandom p = (ParametersWithRandom) params;

            padding.init(p.getRandom());

            cipher.init(forEncryption, p.getParameters());
        }
        else
        {
            if (forEncryption)
            {
                padding.init(null);
            }

            cipher.init(forEncryption, params);
        }

        buf = new byte[cipher.getMultiBlockSize()];
        bufOff = 0;

    }

    /**
     * return the minimum size of the output buffer required for an update
     * plus a doFinal with an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with len bytes of input.
     */
    public int getOutputSize(
            int len)
    {
        int total = len + bufOff;
        int leftOver = total % blockSize;

        if (leftOver == 0)
        {
            if (forEncryption)
            {
                return total + blockSize;
            }

            return total;
        }

        return total - leftOver + blockSize;
    }

    /**
     * return the size of the output buffer required for an update
     * an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    public int getUpdateOutputSize(
            int len)
    {
        int total = len + bufOff;
        int leftOver = total % blockSize;

        if (!forEncryption && leftOver == 0)
        {
            return Math.max(0, total - blockSize);
        }

        return total - leftOver;
    }

    /**
     * process a single byte, producing an output block if neccessary.
     *
     * @param in     the input byte.
     * @param out    the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException   if there isn't enough space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public int processByte(
            byte in,
            byte[] out,
            int outOff)
            throws DataLengthException, IllegalStateException
    {
        int resultLen = 0;

        if (bufOff == buf.length)
        {
            resultLen = cipher.processBlock(buf, 0, out, outOff);
            bufOff = 0;
        }

        buf[bufOff++] = in;

        return resultLen;
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in     the input byte array.
     * @param inOff  the offset at which the input data starts.
     * @param len    the number of bytes to be copied out of the input array.
     * @param out    the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException   if there isn't enough space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public int processBytes(
            byte[] in,
            int inOff,
            int len,
            byte[] out,
            int outOff)
            throws DataLengthException, IllegalStateException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("input length cannot be negative");
        }

        int length = getUpdateOutputSize(len);

        if (length > 0)
        {
            if ((outOff + length) > out.length)
            {
                throw new OutputLengthException("output buffer too short");
            }
        }

        int resultLen = 0;
        int gapLen = buf.length - bufOff;

        if (len > gapLen)
        {
            if (bufOff != 0)
            {
                System.arraycopy(in, inOff, buf, bufOff, gapLen);
                resultLen += cipher.processBlocks(buf, 0, buf.length / blockSize, out, outOff);
                bufOff = 0;
                len -= gapLen;
                inOff += gapLen;
            }

            if (len > buf.length)
            {
                int blockCount;
                if (forEncryption)
                {
                    blockCount = (len / blockSize);
                }
                else
                {
                    blockCount = (len / blockSize) - ((len % blockSize == 0) ? 1 : 0);
                }

                if (blockCount > 0)
                {
                    resultLen += cipher.processBlocks(in, inOff, blockCount, out, outOff + resultLen);

                    int processed = blockCount * blockSize;

                    len -= processed;
                    inOff += processed;

                    // we need to store the last block
                    // in case it affects how we add padding later
                    if (len == 0)
                    {
                        System.arraycopy(in, inOff - blockSize, buf, 0, blockSize);
                    }
                }
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;

        return resultLen;
    }

    /**
     * Process the last block in the buffer. If the buffer is currently
     * full and padding needs to be added a call to doFinal will produce
     * 2 * getBlockSize() bytes.
     *
     * @param out    the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException        if there is insufficient space in out for
     *                                    the output or we are decrypting and the input is not block size aligned.
     * @throws IllegalStateException      if the underlying cipher is not
     *                                    initialised.
     * @throws InvalidCipherTextException if padding is expected and not found.
     */
    public int doFinal(
            byte[] out,
            int outOff)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        int resultLen = 0;

        // TODO: this should be mod blockSize, resultLen calculation needs to be corrected as well.
        if (forEncryption)
        {
            byte[] pad = new byte[blockSize];
            if (bufOff == cipher.getMultiBlockSize())
            {
                if ((outOff + cipher.getMultiBlockSize() + blockSize) > out.length)
                {
                    reset();

                    throw new OutputLengthException("output buffer too short");
                }

                System.arraycopy(buf, bufOff - blockSize, pad, 0, blockSize);
                resultLen = cipher.processBlocks(buf, 0, bufOff / blockSize, out, outOff);
                bufOff = 0;
            }
            else
            {
                if (bufOff == 0)
                {
                    // take into account whole block processing to avoid extra
                    // native calls.
                    System.arraycopy(buf, 0, pad, 0, blockSize);
                }
                else if (bufOff > blockSize)
                {
                    System.arraycopy(buf, ((bufOff / blockSize) - 1) * blockSize, pad, 0, blockSize);
                }
            }

            int padOff = bufOff % blockSize;
            if (padOff != 0)
            {
                System.arraycopy(buf, bufOff - padOff, pad, 0, padOff);
            }

            padding.addPadding(pad, padOff);
            if (bufOff == 0)
            {
                System.arraycopy(pad, 0, buf, 0, blockSize);
                bufOff += blockSize;
            }
            else
            {
                System.arraycopy(pad, 0, buf, (bufOff / blockSize) * blockSize, blockSize);
                bufOff += blockSize - padOff;
            }

            resultLen += cipher.processBlocks(buf, 0, bufOff / blockSize, out, outOff + resultLen);

            reset();
        }
        else
        {
            if (bufOff % blockSize == 0)
            {
                resultLen = cipher.processBlocks(buf, 0, bufOff / blockSize, buf, 0);
            }
            else
            {
                reset();

                throw new DataLengthException("last block incomplete in decryption");
            }

            try
            {
                resultLen -= padding.padCount(Arrays.copyOfRange(buf, resultLen - blockSize, resultLen));

                System.arraycopy(buf, 0, out, outOff, resultLen);
            }
            finally
            {
                reset();
            }
        }

        return resultLen;
    }
}

