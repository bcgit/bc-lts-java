package org.bouncycastle.crypto;

public class ExceptionMessage
{
    public static final String OUTPUT_LENGTH = "output buffer too short";
    public static final String INPUT_LENGTH = "input buffer too short";
    public static final String INPUT_NULL = "input was null";
    public static final String INPUT_OFFSET_NEGATIVE = "input offset is negative";
    public static final String OUTPUT_OFFSET_NEGATIVE = "output offset is negative";
    public static final String LEN_NEGATIVE = "input len is negative";
    public static final String INPUT_SHORT = "data too short";
    public static final String AES_KEY_LENGTH = "key must be only 16,24 or 32 bytes long";
    public static final String AES_DECRYPTION_INPUT_LENGTH_INVALID = "the length of input should be times of 16.";
    public static final String CBC_IV_LENGTH = "iv must be only 16 bytes";
    public static final String OUTPUT_NULL = "output was null";
    public static final String GCM_SIV_UNINITIALIZED = "GCM-SIV is uninitialized";
}
