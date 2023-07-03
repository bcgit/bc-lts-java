package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.InvalidCipherTextException;

public interface CCMModeCipher
    extends AEADBlockCipher
{
    int processPacket(byte[] inBuf, int i, int length, byte[] outBuf, int i1) throws InvalidCipherTextException;

    byte[] processPacket(byte[] c2, int i, int length) throws InvalidCipherTextException;
}
