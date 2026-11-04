package org.bouncycastle.util.io;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * Utility methods to assist with stream processing.
 */
public final class Streams
{
    private static int BUFFER_SIZE = 4096;

    /**
     * Read stream till EOF is encountered.
     *
     * @param inStr stream to be emptied.
     * @throws IOException in case of underlying IOException.
     */
    public static void drain(InputStream inStr)
        throws IOException
    {
        byte[] bs = new byte[BUFFER_SIZE];
        while (inStr.read(bs, 0, bs.length) >= 0)
        {
        }
    }

    /**
     * Write the full contents of inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException.
     */
    public static void pipeAll(InputStream inStr, OutputStream outStr)
        throws IOException
    {
        pipeAll(inStr, outStr, BUFFER_SIZE);
    }

    /**
     * Write the full contents of inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param outStr destination output stream.
     * @param bufferSize the size of temporary buffer to use.
     * @throws IOException in case of underlying IOException.
     */
    public static void pipeAll(InputStream inStr, OutputStream outStr, int bufferSize)
        throws IOException
    {
        byte[] bs = new byte[bufferSize];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            outStr.write(bs, 0, numRead);
        }
    }

    /**
     * Write up to limit bytes of data from inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param limit the maximum number of bytes allowed to be read.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static long pipeAllLimited(InputStream inStr, long limit, OutputStream outStr)
        throws IOException
    {
        long total = 0;
        byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            if ((limit - total) < numRead)
            {
                throw new StreamOverflowException("Data Overflow");
            }
            total += numRead;
            outStr.write(bs, 0, numRead);
        }
        return total;
    }

    /**
     * Read stream fully, returning contents in a byte array.
     *
     * @param inStr stream to be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException.
     */
    public static byte[] readAll(InputStream inStr)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAll(inStr, buf);
        return buf.toByteArray();
    }

    /**
     * Read from inStr up to a maximum number of bytes, throwing an exception if more the maximum amount
     * of requested data is available.
     *
     * @param inStr stream to be read.
     * @param limit maximum number of bytes that can be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static byte[] readAllLimited(InputStream inStr, int limit)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAllLimited(inStr, limit, buf);
        return buf.toByteArray();
    }

    /**
     * Fully read in buf's length in data, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(InputStream inStr, byte[] buf)
        throws IOException
    {
        return readFully(inStr, buf, 0, buf.length);
    }

    /**
     * Fully read in len's bytes of data into buf, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @param off offset into buf to start putting bytes into.
     * @param len  the number of bytes to be read.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        int totalRead = 0;
        while (totalRead < len)
        {
            int numRead = inStr.read(buf, off + totalRead, len - totalRead);
            if (numRead < 0)
            {
                break;
            }
            totalRead += numRead;
        }

        return totalRead;
    }

    /**
     * Chunk size for the incremental reader in {@link #readLenBytesFully(InputStream, int)}: 64 KiB, a power
     * of two with headroom under every collector's large-object line - G1 treats an object of half a region
     * or more as humongous (512 KiB at the 1 MiB minimum region size), ZGC's small pages take objects up to
     * 256 KiB, and Shenandoah's smallest region is 256 KiB. A byte[] also carries a header, so a payload of
     * exactly one of those sizes would already cross it.
     */
    private static final int ROPE_CHUNK_SIZE = 1 << 16;

    /**
     * Safety fraction for the incremental reader, as a shift: a quarter of the data must arrive before the
     * full-length allocation, which bounds the bytes allocated at five times the bytes delivered.
     */
    private static final int ROPE_SHIFT = 2;

    /**
     * Read exactly {@code len} bytes from {@code inStr} and return them as a newly allocated array.
     * <p>
     * Unlike {@code new byte[len]} followed by {@link #readFully(InputStream, byte[])}, the full-length
     * array is not allocated until the stream has actually delivered a quarter of the declared length, so
     * a caller passing an untrusted (possibly hostile) length cannot drive a large allocation from a short
     * input: a stream that ends before {@code len} bytes have been read fails with an {@link EOFException},
     * having caused at most five times the delivered bytes plus 128 KiB to be allocated.
     * <p>
     * Lengths up to 128 KiB are allocated up front and read directly. Above that, the first quarter of the
     * data is read into a rope of 64 KiB chunks, each allocated just ahead of its own fill; the result is
     * then allocated once, the chunks copied into it and the remainder read directly into it. The only
     * intermediate arrays are the chunks, so a read leaves no large-object garbage behind - a geometrically
     * grown single buffer would instead leave one humongous array per doubling on G1 and the other region
     * based collectors. The chunks are fresh zeroed arrays that are never reused: the stream is handed a
     * reference to each of them, so pooling would not be hygienic.
     *
     * @param inStr the stream to read from.
     * @param len   the exact number of bytes to read.
     * @return a {@code byte[len]} containing the bytes read.
     * @throws EOFException if the stream ends before {@code len} bytes are available.
     * @throws IOException  on an underlying read error.
     * @throws IllegalArgumentException if {@code len} is negative.
     */
    public static byte[] readLenBytesFully(InputStream inStr, int len)
        throws IOException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("len cannot be negative");
        }

        // Small lengths are read directly: the up-front allocation is bounded by the cutoff, and a rope
        // phase would cost an extra allocation and copy to defer at most that much.
        if (len <= 2 * ROPE_CHUNK_SIZE)
        {
            byte[] bytes = new byte[len];
            readFullyOrThrow(inStr, bytes, 0, len);
            return bytes;
        }

        // The chunk count is known up front (bounded at 8192 references for any int length), so the rope
        // can be a plain array rather than a growing list.
        int threshold = len >> ROPE_SHIFT;
        byte[][] chunks = new byte[(threshold + ROPE_CHUNK_SIZE - 1) / ROPE_CHUNK_SIZE][];
        int received = 0;
        for (int i = 0; received < threshold; ++i)
        {
            // The last rope chunk is capped so that the rope phase ends exactly at the threshold; the total
            // allocation is then (1 + 1/4) len for every length above the cutoff.
            int chunkSize = Math.min(ROPE_CHUNK_SIZE, threshold - received);
            byte[] chunk = new byte[chunkSize];
            readFullyOrThrow(inStr, chunk, 0, chunkSize);
            chunks[i] = chunk;
            received += chunkSize;
        }

        byte[] result = new byte[len];

        // Copy the chunks in first, while they are still cache-warm and before the remainder read can stall.
        int pos = 0;
        for (int i = 0; i < chunks.length; ++i)
        {
            byte[] chunk = chunks[i];
            System.arraycopy(chunk, 0, result, pos, chunk.length);
            pos += chunk.length;
        }

        readFullyOrThrow(inStr, result, received, len - received);
        return result;
    }

    private static void readFullyOrThrow(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        while (len > 0)
        {
            int numRead = inStr.read(buf, off, len);
            if (numRead < 0)
            {
                throw new EOFException("premature end of stream");
            }
            off += numRead;
            len -= numRead;
        }
    }

    public static void validateBufferArguments(byte[] buf, int off, int len)
    {
        Arrays.validateSegment(buf, off, len);
    }

    public static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
        throws IOException
    {
        buf.writeTo(output);
    }
}
