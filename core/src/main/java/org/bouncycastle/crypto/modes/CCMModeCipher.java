package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.InvalidCipherTextException;

public interface CCMModeCipher
    extends AEADBlockCipher
{
    int processPacket(byte[] inBuf, int inOffset, int length, byte[] outBuf, int outOffset) throws InvalidCipherTextException;

    byte[] processPacket(byte[] c2, int inOffset, int length) throws InvalidCipherTextException;
}
