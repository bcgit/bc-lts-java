//
// Created  on 4/7/2022.
//

#include <cstring>
#include "debug.h"

#include "debug.h"

/*!
 * Helper function to convert bit size into byte size.
 *
 * \param[in] Size in bits
 *
 * \return size in bytes
 */
static int bitSizeInBytes(int nBits) {
    return (nBits + 7) >> 3;
}

/*!
 * Helper function to convert bit size into word size.
 *
 * \param[in] Size in bits
 *
 * \return size in words
 */

static int bitSizeInWords(int nBits) {
    return (nBits + 31) >> 5;
}

/*! Macro that prints status message depending on condition */
#define PRINT_EXAMPLE_STATUS(function_name, description, success_condition)       \
    printf("+--------------------------------------------------------------|\n"); \
    printf(" Function: %s\n", function_name);                                     \
    printf(" Description: %s\n", description);                                    \
    if (success_condition) {                                                      \
        printf(" Status: PASSED!\n");                                             \
    } else {                                                                      \
        printf(" Status: FAILED!\n");                                             \
    }                                                                             \
    printf("+--------------------------------------------------------------|\n");




int main() {

    int t = 1;
    throwIfNot(t == 0, "Cats");

    exit:
    return 0;


}


//
///*! Public exponent */
//static intel::BigNumber E("0x11");
//
///*! Plain text source message */
//static Ipp8u sourceMessage[] =
//        "\xd4\x36\xe9\x95\x69\xfd\x32\xa7"
//        "\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49";
//
///*! Seed string of hash size */
//static Ipp8u seed[] = "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4"
//                      "\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f";
//
///*! Reference cipher text. Length is equal to RSA modulus size */
//static Ipp8u cipherTextRef[] =
//        "\x12\x53\xE0\x4D\xC0\xA5\x39\x7B\xB4\x4A\x7A\xB8\x7E\x9B\xF2\xA0"
//        "\x39\xA3\x3D\x1E\x99\x6F\xC8\x2A\x94\xCC\xD3\x00\x74\xC9\x5D\xF7"
//        "\x63\x72\x20\x17\x06\x9E\x52\x68\xDA\x5D\x1C\x0B\x4F\x87\x2C\xF6"
//        "\x53\xC1\x1D\xF8\x23\x14\xA6\x79\x68\xDF\xEA\xE2\x8D\xEF\x04\xBB"
//        "\x6D\x84\xB1\xC3\x1D\x65\x4A\x19\x70\xE5\x78\x3B\xD6\xEB\x96\xA0"
//        "\x24\xC2\xCA\x2F\x4A\x90\xFE\x9F\x2E\xF5\xC9\xC1\x40\xE5\xBB\x48"
//        "\xDA\x95\x36\xAD\x87\x00\xC8\x4F\xC9\x13\x0A\xDE\xA7\x4E\x55\x8D"
//        "\x51\xA7\x4D\xDF\x85\xD8\xB5\x0D\xE9\x68\x38\xD6\x06\x3E\x09\x55";
//
//
///* Internal function status */
//IppStatus status = ippStsNoErr;
//
///* Size in bits of RSA modulus */
//const int bitSizeN = N.BitSize();
///* Size in bits of RSA public exponent */
//const int bitSizeE = E.BitSize();
//
///* Allocate memory for public key. */
//int keySize = 0;
//ippsRSA_GetSizePublicKey(bitSizeN, bitSizeE, &keySize);
//IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)(new Ipp8u[keySize]);
//ippsRSA_InitPublicKey(bitSizeN, bitSizeE, pPubKey, keySize);
//
//
///* Allocate memory for cipher text, not less than RSA modulus size. */
//int cipherTextLen = bitSizeInBytes(bitSizeN);
//Ipp8u* pCipherText = new Ipp8u[cipherTextLen];
//
//do {
///* Set public key */
//status = ippsRSA_SetPublicKey(N, E, pPubKey);
//if (!checkStatus("ippsRSA_SetPublicKey", ippStsNoErr, status))
//break;
//
///* Calculate temporary buffer size */
//int pubBufSize = 0;
//status = ippsRSA_GetBufferSizePublicKey(&pubBufSize, pPubKey);
//if (!checkStatus("ippsRSA_GetBufferSizePublicKey", ippStsNoErr, status))
//break;
//
///* Allocate memory for temporary buffer */
//Ipp8u* pScratchBuffer = new Ipp8u[pubBufSize];
//
///* Encrypt message */
//status = ippsRSAEncrypt_OAEP_rmf(sourceMessage, sizeof(sourceMessage)-1,
//                                 0  /* optional label assotiated with the sourceMessage */,
//                                 0, /* label length */
//                                 seed, pCipherText, pPubKey,
//                                 ippsHashMethod_SHA1(),
//                                 pScratchBuffer);
//
//if (pScratchBuffer) delete [] pScratchBuffer;
//
//if (!checkStatus("ippsRSAEncrypt_OAEP_rmf", ippStsNoErr, status))
//break;
//
//if (0 != memcmp(cipherTextRef, pCipherText, sizeof(cipherTextRef)-1)) {
//printf("ERROR: Encrypted and reference messages do not match\n");
//status = ippStsErr;
//}
//} while (0);
//
//PRINT_EXAMPLE_STATUS("ippsRSAEncrypt_OAEP_rmf", "RSA-OAEP 1024 (SHA1) Encryption", ippStsNoErr == status);
//
//if (pCipherText) delete [] pCipherText;
//if (pPubKey) delete [] (Ipp8u*)pPubKey;
//
//return status;


/*
 *
//    auto _data = (from_hex("FF1100110011001100110011001100AA"));
//
//    __m128i a = _mm_loadu_si128((__m128i_u *) (from_hex("0102030405060708090a0b0c0d0e0f10")));
//    __m128i b = _mm_loadu_si128((__m128i_u *) from_hex("0102030405060708090a0b0c0d0e0f10"));
//
//    auto S_at = a;
//    auto H = b;
//
//    __m128i data = _mm_loadu_si128((__m128i_u *) _data);
//
//    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
//
//    data = _mm_shuffle_epi8(data, BSWAP_MASK);
//    print_bytes("data_shuffle", &data);
//
//
//    print_bytes("s_at", &S_at);



    auto userKey = from_hex("00000000000000000000000000000000");
    auto in = from_hex("0000000000000000000000000000000080000000000000000000000000000000");
    //  auto out = from_hex("6CD02513E8D4DC986B4AFE087A60BD0C");
    auto iv = from_hex("00000000000000000000000000000000");


    unsigned char res[256];
    memset(res, 0, 256);

    intel::Config::configure(0);

    auto ecb = intel::cbc::CBC::makeCBC();

    ecb->init(true, userKey, 16, iv, 16);
    ecb->processBlock(in, 2, res);

    print_bytes("enc", res, 32);

    ecb->init(false, userKey, 16, iv, 16);
    ecb->processBlock(res, 2, res);

    print_bytes("dec", res, 32);

    delete ecb;


//    __m128i roundKeys[15];
//    memset(roundKeys, 0, 15 * sizeof(__m128i));
//
//
//    auto userKey = from_hex("0100000000000000000000000000000000000000000000000000000000000000");
//    _aes_256_expand(roundKeys, userKey, false);
//
//    for (int t = 0; t < 15; t++) {
//        print_bytes(&roundKeys[t]);
//    }
//
//    std::cout << "---- " << std::endl;
//
//    memset(roundKeys, 0, 15 * sizeof(__m128i));
//    intel::aes::init(14, false, roundKeys, userKey);
//
//    for (int t = 0; t < 15; t++) {
//        print_bytes(&roundKeys[t]);
//    }
//
//    delete[] userKey;

 */