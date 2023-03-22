package org.bouncycastle.crypto;

public interface BufferedBlockCipher
{
    BlockCipher getUnderlyingCipher();

    void init(
            boolean forEncryption,
            CipherParameters params)
            throws IllegalArgumentException;

    int getBlockSize();

    int getUpdateOutputSize(
            int len);

    int getOutputSize(
            int length);

    int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException;

    int processBytes(
            byte[] in,
            int inOff,
            int len,
            byte[] out,
            int outOff)
            throws DataLengthException, IllegalStateException;

    int doFinal(
            byte[] out,
            int outOff)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException;

    void reset();


}