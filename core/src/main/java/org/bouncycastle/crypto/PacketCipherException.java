package org.bouncycastle.crypto;

public class PacketCipherException extends Exception
{
    private final Reason reason;

    public enum Reason
    {
        INVALID_CIPHERTEXT,
        OUTPUT_LENGTH,
        DATA_LENGTH,
        OTHER
    }

    public static PacketCipherException from(Throwable throwable)
    {
        if (throwable instanceof InvalidCipherTextException)
        {
            return new PacketCipherException(Reason.INVALID_CIPHERTEXT, throwable.getMessage(), throwable);
        }
        else if (throwable instanceof OutputLengthException)
        {
            return new PacketCipherException(Reason.OUTPUT_LENGTH, throwable.getMessage(), throwable);
        }
        else if (throwable instanceof DataLengthException)
        {
            return new PacketCipherException(Reason.DATA_LENGTH, throwable.getMessage(), throwable);
        }
        return new PacketCipherException(Reason.OTHER, throwable.getMessage(), throwable);
    }

    private PacketCipherException(Reason reason, String message, Throwable cause)
    {
        super(message, cause);
        this.reason = reason;
    }

    @Override
    public String toString()
    {
        return reason.toString() + " " + super.toString();
    }

    public Reason getReason()
    {
        return reason;
    }
}
