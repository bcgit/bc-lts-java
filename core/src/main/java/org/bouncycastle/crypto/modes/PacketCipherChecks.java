package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.PacketCipherException;

public class PacketCipherChecks
{
    protected static void checkBoundsInput(byte[] input, int inOff, int len, byte[] output, int outOff)
            throws PacketCipherException
    {
        if (input == null)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INPUT_NULL));
        }

        if (output == null)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.OUTPUT_NULL));
        }

        if (inOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INPUT_OFFSET_NEGATIVE));
        }

        if (outOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.OUTPUT_OFFSET_NEGATIVE));
        }

        if (len < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE));
        }

        if (inOff > input.length - len)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessages.INPUT_TOO_SHORT));
        }
    }


    static void checkBoundsInputAndOutputWithBlockSize_16(byte[] input, int inOff, int len, byte[] output
            , int outOff)
            throws PacketCipherException
    {
        checkBoundsInputAndOutput(input, inOff, len, output, outOff);
        if (len % 16 != 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.BLOCK_CIPHER_16_INPUT_LENGTH_INVALID));
        }
    }


    static void checkBoundsInputAndOutput(byte[] input, int inOff, int len, byte[] output, int outOff)
            throws PacketCipherException
    {
        if (input == null)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INPUT_NULL));
        }

        if (output == null)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.OUTPUT_NULL));
        }

        if (inOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INPUT_OFFSET_NEGATIVE));
        }

        if (outOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.OUTPUT_OFFSET_NEGATIVE));
        }

        if (len < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE));
        }

        if (inOff > input.length - len)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessages.INPUT_TOO_SHORT));
        }

        if (outOff > output.length - len)
        {
            throw PacketCipherException.from(new OutputLengthException(ExceptionMessages.OUTPUT_LENGTH));
        }

    }

    static void checkInputAgainstRequiredLength(byte[] input, int inOff, int requiredLength) throws PacketCipherException{

        if (inOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.INPUT_OFFSET_NEGATIVE));
        }

        if (requiredLength < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE));
        }

        if (inOff > input.length - requiredLength)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessages.INPUT_SHORT));
        }
    }


    static void checkOutputAgainstRequiredLength(byte[] output, int outOff, int requiredLength) throws PacketCipherException{

        if (outOff < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.OUTPUT_OFFSET_NEGATIVE));
        }

        if (requiredLength < 0)
        {
            throw PacketCipherException.from(new IllegalArgumentException(ExceptionMessages.LEN_NEGATIVE));
        }

        if (outOff > output.length - requiredLength)
        {
            throw PacketCipherException.from(new DataLengthException(ExceptionMessages.OUTPUT_LENGTH));
        }
    }

    static int addCheckInputOverflow(int a, int b)
    {

        assert a >= 0;
        assert b >= 0;
        try
        {
            return Math.addExact(a, b);
        }
        catch (ArithmeticException arex)
        {
            throw new DataLengthException(ExceptionMessages.INPUT_OVERFLOW);
        }
    }


    protected static void checkKeyLength(int keyLen) throws PacketCipherException
    {
        try
        {
            checkKeyLenIllegalArgumentException(keyLen);
        }
        catch (IllegalArgumentException ilex)
        {
            throw PacketCipherException.from(ilex);
        }
    }

    protected static void checkKeyLenIllegalArgumentException(int keyLen)
    {
        switch (keyLen)
        {
            case 16:
            case 24:
            case 32:
                break;
            default:
                throw new IllegalArgumentException(ExceptionMessages.AES_KEY_LENGTH);
        }
    }

}
