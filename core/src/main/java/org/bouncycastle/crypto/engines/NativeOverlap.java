package org.bouncycastle.crypto.engines;

/**
 * Overlapping input and output for the native AES modes whose output is the same length as their
 * input. The native code works through the buffers in order, so output written ahead of the input
 * in the same array would overwrite input it has yet to read; this moves the input to where the
 * output goes first, so it is processed in place, as the java stream ciphers do. Only an output
 * that starts after the input and overlaps it moves anything: in place and output behind the input
 * are already safe and cost nothing here. Out of range arguments are left alone for the native
 * code to reject as it always has.
 */
class NativeOverlap
{
    private NativeOverlap()
    {
    }

    /**
     * Return the offset to read the input from: inOff, or outOff once the input has been moved there.
     */
    static int inputOffset(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
        if (in == out && in != null && inOff >= 0 && len >= 0 && inOff < outOff && outOff - inOff < len
            && outOff <= out.length - len)
        {
            System.arraycopy(in, inOff, out, outOff, len);
            return outOff;
        }

        return inOff;
    }
}
