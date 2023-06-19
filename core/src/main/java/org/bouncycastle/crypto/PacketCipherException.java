package org.bouncycastle.crypto;

public class PacketCipherException extends Exception
{
    public PacketCipherException()
    {
    }

    public PacketCipherException(String message)
    {
        super(message);
    }

    public PacketCipherException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public PacketCipherException(Throwable cause)
    {
        super(cause);
    }

}
