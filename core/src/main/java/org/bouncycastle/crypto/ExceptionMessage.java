package org.bouncycastle.crypto;

public class ExceptionMessage
{
    public static final String OUTPUT_LENGTH = "output buffer too short";
    public static final String INPUT_LENGTH = "input buffer too short";
    public static final String INPUT_NULL = "input was null";
    public static final String INPUT_OFFSET_NEGATIVE = "offset is negative";
    public static final String OUTPUT_OFFSET_NEGATIVE = "output offset is negative";
    public static final String LEN_NEGATIVE = "len is negative";
    public static final String INPUT_SHORT = "data too short";
    public static final String AES_KEY_LENGTH = "Key length not 128/192/256 bits.";
    public static final String AES_DECRYPTION_INPUT_LENGTH_INVALID = "the length of input should be times of 16.";
    public static final String CBC_IV_LENGTH = "initialisation vector must be the same length as block size";
    public static final String OUTPUT_NULL = "output was null";
}
