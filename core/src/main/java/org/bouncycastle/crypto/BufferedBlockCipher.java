package org.bouncycastle.crypto;

public interface BufferedBlockCipher
    extends BlockCipher
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