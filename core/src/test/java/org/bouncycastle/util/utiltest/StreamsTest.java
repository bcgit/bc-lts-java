package org.bouncycastle.util.utiltest;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class StreamsTest
    extends TestCase
{
    private static final long FIXED_SEED = 0x5EED;
    private static final int DATA_SIZE = 1 << 24;
    private static final int CHUNK_SIZE = 1 << 16;
    private static final int CHUNKY_MAX_READ = 1 << 14;
    private static final int TRICKLE_MAX_READ = 3;

    // Serve the whole request per read (ByteArrayInputStream-like), a random 1..16 KiB per read
    // (network-like), or a random 1..3 bytes per read (worst case for the fill loops).
    private static final int MODE_FULL = 0;
    private static final int MODE_CHUNKY = 1;
    private static final int MODE_TRICKLE = 2;
    private static final String[] MODE_NAMES = { "full", "chunky", "trickle" };

    // Boundaries of the reader (direct read up to two 64 KiB chunks; above that, chunk multiples and
    // sizes whose quarter is or is not a chunk multiple, e.g. 256K, 512K), their neighbours, and some
    // arbitrary sizes.
    private static final int[] EDGE_SIZES = {
        0, 1, 2, 3, 4095, 4096, 4097, 65535, 65536, 65537, 131071, 131072, 131073, 262143, 262144, 262145,
        327679, 327680, 327681, 524287, 524288, 524289, 1000003, (1 << 22) + 12345, (1 << 24) - 1, 1 << 24,
    };

    private static byte[] data;

    private static synchronized byte[] getData()
    {
        if (data == null)
        {
            byte[] d = new byte[DATA_SIZE];
            new Random(FIXED_SEED).nextBytes(d);
            data = d;
        }
        return data;
    }

    private static int[] getTestSizes()
    {
        int[] sizes = new int[EDGE_SIZES.length + 12];
        System.arraycopy(EDGE_SIZES, 0, sizes, 0, EDGE_SIZES.length);

        Random rng = new Random(FIXED_SEED);
        for (int i = EDGE_SIZES.length; i < sizes.length; ++i)
        {
            sizes[i] = rng.nextInt(1 << 21);
        }
        return sizes;
    }

    private static int getMaxRead(int mode)
    {
        switch (mode)
        {
        case MODE_FULL:
            return 0;
        case MODE_CHUNKY:
            return CHUNKY_MAX_READ;
        case MODE_TRICKLE:
            return TRICKLE_MAX_READ;
        default:
            throw new IllegalArgumentException("mode");
        }
    }

    public void testReadLenBytesFully()
        throws IOException
    {
        // exact length, spanning multiple internal read chunks (length > the internal buffer size)
        byte[] data = new byte[10000];
        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)i;
        }

        byte[] read = Streams.readLenBytesFully(new ByteArrayInputStream(data), data.length);
        assertTrue(Arrays.areEqual(data, read));

        // a prefix shorter than the available data is read exactly
        byte[] prefix = Streams.readLenBytesFully(new ByteArrayInputStream(data), 100);
        assertEquals(100, prefix.length);
        assertTrue(Arrays.areEqual(Arrays.copyOf(data, 100), prefix));
    }

    public void testReadLenBytesFullyZeroLength()
        throws IOException
    {
        byte[] read = Streams.readLenBytesFully(new ByteArrayInputStream(new byte[]{ 1, 2, 3 }), 0);
        assertEquals(0, read.length);
    }

    public void testReadLenBytesFullyPartialReads()
        throws IOException
    {
        // a stream that yields one byte per read call must still be fully assembled
        byte[] data = new byte[1000];
        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)(i * 7);
        }

        byte[] read = Streams.readLenBytesFully(new OneByteAtATimeInputStream(data), data.length);
        assertTrue(Arrays.areEqual(data, read));
    }

    public void testReadLenBytesFullyShortStreamThrows()
    {
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), 20);
            fail("no exception");
        }
        catch (EOFException e)
        {
            assertEquals("premature end of stream", e.getMessage());
        }
        catch (IOException e)
        {
            fail("wrong exception: " + e);
        }
    }

    public void testReadLenBytesFullyHostileLengthDoesNotOverAllocate()
    {
        // A declared length far larger than the data available must fail fast with an EOFException
        // rather than pre-allocating new byte[Integer.MAX_VALUE] (the github #2338 DoS class): the
        // call returns promptly without an OutOfMemoryError because allocation tracks delivered bytes.
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), Integer.MAX_VALUE);
            fail("no exception");
        }
        catch (EOFException e)
        {
            assertEquals("premature end of stream", e.getMessage());
        }
        catch (IOException e)
        {
            fail("wrong exception: " + e);
        }
    }

    public void testReadLenBytesFullyNegativeLength()
        throws IOException
    {
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), -1);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("len cannot be negative", e.getMessage());
        }
    }

    public void testReadLenBytesFullyExactAcrossSources()
        throws IOException
    {
        byte[] data = getData();
        int[] sizes = getTestSizes();

        for (int mode = MODE_FULL; mode <= MODE_TRICKLE; ++mode)
        {
            SegmentedInputStream source = new SegmentedInputStream(data, getMaxRead(mode));

            for (int i = 0; i < sizes.length; ++i)
            {
                int size = sizes[i];

                // Trickle mode is slow at large sizes and exercises nothing new there.
                if (mode == MODE_TRICKLE && size > 300000)
                {
                    continue;
                }

                String label = MODE_NAMES[mode] + " size " + size;
                source.reset(size, FIXED_SEED ^ size);

                byte[] bytes = Streams.readLenBytesFully(source, size);
                assertEquals(label, size, bytes.length);
                assertTrue(label + " contents", Arrays.areEqual(data, 0, size, bytes, 0, size));

                // The source must have been asked for exactly the data and nothing more.
                assertEquals(label + " remaining", 0, source.remaining());
                assertEquals(label + " over-read", -1, source.read(new byte[1], 0, 1));
            }
        }
    }

    public void testReadLenBytesFullyShortInputThrows()
        throws IOException
    {
        byte[] data = getData();
        int[] sizes = getTestSizes();

        for (int mode = MODE_FULL; mode <= MODE_CHUNKY; ++mode)
        {
            SegmentedInputStream source = new SegmentedInputStream(data, getMaxRead(mode));

            for (int i = 0; i < sizes.length; ++i)
            {
                int size = sizes[i];
                if (size == 0)
                {
                    continue;
                }

                // EOF inside the direct path, inside the first or a later rope chunk, exactly at the
                // threshold, and inside the remainder.
                int[] shortfalls = { 1, 4096, 65536, size / 2, size - 1, size };
                for (int j = 0; j < shortfalls.length; ++j)
                {
                    int shortfall = shortfalls[j];
                    int limit = size - shortfall;
                    if (shortfall < 1 || limit < 0)
                    {
                        continue;
                    }

                    String label = MODE_NAMES[mode] + " size " + size + " limit " + limit;
                    source.reset(limit, FIXED_SEED ^ size);

                    try
                    {
                        Streams.readLenBytesFully(source, size);
                        fail(label + ": no exception");
                    }
                    catch (EOFException e)
                    {
                        assertEquals(label, "premature end of stream", e.getMessage());
                    }
                }
            }
        }
    }

    public void testReadLenBytesFullyAllocatesIncrementally()
        throws IOException
    {
        // A 16 MiB request against a stream that ends after 200 000 bytes: nothing larger than a rope
        // chunk may have been handed to the stream, and the total handed over tracks the delivered
        // bytes (at most four chunks here) - the full-length array is never allocated.
        BufferTrackingInputStream source = new BufferTrackingInputStream(200000);

        try
        {
            Streams.readLenBytesFully(source, 1 << 24);
            fail("no exception");
        }
        catch (EOFException e)
        {
            assertEquals("premature end of stream", e.getMessage());
        }

        assertTrue("largest buffer " + source.largestBuffer, source.largestBuffer <= CHUNK_SIZE);
        assertTrue("total buffers " + source.totalBufferBytes, source.totalBufferBytes <= 4 * CHUNK_SIZE);

        // Once a quarter of the data has arrived the full-length array is handed over, once.
        source = new BufferTrackingInputStream(1 << 24);
        byte[] bytes = Streams.readLenBytesFully(source, 1 << 24);
        assertEquals(1 << 24, bytes.length);
        assertEquals(1 << 24, source.largestBuffer);
        assertEquals((1 << 24) + (1 << 22), source.totalBufferBytes);
    }

    private static class OneByteAtATimeInputStream
        extends InputStream
    {
        private final byte[] data;
        private int pos = 0;

        OneByteAtATimeInputStream(byte[] data)
        {
            this.data = data;
        }

        public int read()
        {
            return pos >= data.length ? -1 : (data[pos++] & 0xff);
        }

        public int read(byte[] b, int off, int len)
        {
            if (pos >= data.length)
            {
                return -1;
            }
            if (len <= 0)
            {
                return 0;
            }
            b[off] = data[pos++];
            return 1;  // deliberately one byte per call to exercise the accumulation loop
        }
    }

    /**
     * Serves a prefix of a byte array, at most maxRead bytes per call (a random 1..maxRead when maxRead
     * is positive, everything asked for when it is zero).
     */
    private static class SegmentedInputStream
        extends InputStream
    {
        private final byte[] data;
        private final int maxRead;
        private int limit;
        private int pos;
        private Random rng;

        SegmentedInputStream(byte[] data, int maxRead)
        {
            this.data = data;
            this.maxRead = maxRead;
        }

        void reset(int limit, long seed)
        {
            this.limit = limit;
            this.pos = 0;
            this.rng = maxRead > 0 ? new Random(seed) : null;
        }

        int remaining()
        {
            return limit - pos;
        }

        public int read()
        {
            return pos >= limit ? -1 : (data[pos++] & 0xff);
        }

        public int read(byte[] b, int off, int len)
        {
            if (len <= 0)
            {
                return 0;
            }

            int avail = limit - pos;
            if (avail <= 0)
            {
                return -1;
            }

            int n = Math.min(len, avail);
            if (rng != null)
            {
                n = Math.min(n, 1 + rng.nextInt(maxRead));
            }

            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /**
     * Serves limit zero bytes, recording the distinct buffers it is handed: the largest, and the total of
     * their lengths.
     */
    private static class BufferTrackingInputStream
        extends InputStream
    {
        private final int limit;
        private int pos;
        private byte[] lastBuffer;
        int largestBuffer;
        long totalBufferBytes;

        BufferTrackingInputStream(int limit)
        {
            this.limit = limit;
        }

        public int read()
        {
            if (pos >= limit)
            {
                return -1;
            }
            pos++;
            return 0;
        }

        public int read(byte[] b, int off, int len)
        {
            if (b != lastBuffer)
            {
                lastBuffer = b;
                largestBuffer = Math.max(largestBuffer, b.length);
                totalBufferBytes += b.length;
            }

            if (len <= 0)
            {
                return 0;
            }

            int avail = limit - pos;
            if (avail <= 0)
            {
                return -1;
            }

            int n = Math.min(len, avail);
            pos += n;
            return n;
        }
    }
}
