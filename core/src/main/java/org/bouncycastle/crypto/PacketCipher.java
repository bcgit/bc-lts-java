package org.bouncycastle.crypto;

/**
 * Packet ciphers are reusable instances that perform one complete transformation
 * with known input and output message lengths.
 */
public interface PacketCipher
{

    /**
     * Returns the expected output size for direction and parameters.
     *
     * @param direction  The direction, encrypt, decrypt etc
     * @param parameters The cipher parameters
     * @param len        the input length.
     * @return the required minimum output length in bytes.
     */
    int getOutputSize(boolean direction, CipherParameters parameters, int len);

    /**
     * Process a packet.
     *
     * @param direction  The Direction. Eg: Encrypt, Decrypt etc
     * @param parameters The key parameters
     * @param input      The input byte array
     * @param inOff      Offset within byte array to start reading input.
     * @param len        the number of bytes of input to process.
     * @param output     The output array
     * @param outOff     the offset within the output array to start writing output.
     * @throws PacketCipherException if the transformation encounters an error.
     */
    void processPacket(boolean direction, CipherParameters parameters, byte[] input, int inOff, int len,
                       byte[] output, int outOff) throws PacketCipherException;
}
