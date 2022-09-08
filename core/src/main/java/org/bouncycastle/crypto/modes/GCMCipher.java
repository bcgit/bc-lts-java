package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface GCMCipher extends AEADBlockCipher
{
     void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException;

     BlockCipher getUnderlyingCipher();

    void processAADByte(byte in);

    void processAADBytes(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException;

    int doFinal(byte[] out, int outOff) throws InvalidCipherTextException;

    void reset();
}
