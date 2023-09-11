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
    public static final String BLOCK_CIPHER_16_INPUT_LENGTH_INVALID = "the length of input should be times of 16.";
    public static final String CBC_IV_LENGTH = "iv must be only 16 bytes";
    public static final String OUTPUT_NULL = "output was null";
    public static final String GCM_SIV_UNINITIALIZED = "GCM-SIV is uninitialized";
    public static final String INVALID_PARAM_TYPE = "invalid parameter type";
    public static final String CBC_CIPHER_UNITIALIZED = "CBC cipher unitialized";
    public static final String CCM_CIPHER_UNITIALIZED = "CCM cipher unitialized";
    public static final String CFB_CIPHER_UNITIALIZED = "CFB cipher unitialized";
    public static final String CTR_CIPHER_UNITIALIZED = "CTR/SIC cipher unitialized.";
    public static final String CCM_MAC_SIZE = "tag length in octets must be one of {4,6,8,10,12,14,16}";
    public static final String CCM_IV_SIZE = "nonce must have length from 7 to 13 octets";
    public static final String CCM_INVALID_PARAMETER = "invalid parameters passed to CCM";
    public static final String GCM_INVALID_PARAMETER = "invalid parameters passed to GCM";
    public static final String CTR_INVALID_PARAMETER = "CTR/SIC mode requires ParametersWithIV";
    public static final String GCM_SIV_INVALID_PARAMETER = "invalid parameters passed to GCM-SIV";
    public static final String CTR16_IV_TOO_LONG = "CTR/SIC mode requires IV no greater than: 16 bytes.";
    public static final String CTR16_IV_TOO_SHORT = "CTR/SIC mode requires IV of at least: 8 bytes.";
    public static final String GCM_INVALID_MAC_SIZE = "Invalid value for MAC size: ";
    public static final String GCM_IV_TOO_SHORT = "IV must be at least 12 byte";
    public static final String GCM_SIV_IV_SIZE = "Invalid nonce";
}
