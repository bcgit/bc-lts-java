//
// Created  on 4/7/2022.
//

#include <cstring>
#include "debug.h"

#include "jniutil/JavaEnvUtils.h"
#include "jniutil/JavaByteArray.h"

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

/*!
 * Helper function to compare expected and actual function return statuses and display
 * an error mesage if those are different.
 *
 * \param[in] Function name to display
 * \param[in] Expected status
 * \param[in] Actual status
 *
 * \return zero if statuses are not equal, otherwise - non-zero value
 */
static int checkStatus(const char *funcName, IppStatus expectedStatus, IppStatus status) {
    if (expectedStatus != status) {
        printf("%s: unexpected return status\n", funcName);
        printf("Expected: %s\n", ippcpGetStatusString(expectedStatus));
        printf("Received: %s\n", ippcpGetStatusString(status));
        return 1;
    }
    return 0;
}


void swap_(char *val, int len) {
    char *right = (char *) val + len - 1;
    char *left = (char *) val;
    while (left < right) {
        std::swap(*left, *right);
        left++;
        right--;
    }
}


void printBig(intel::BigNumber *v) {
    std::string s;
    v->num2hex(s);
    std::cout << s << std::endl;
}


int main() {


    auto p =
            LeLe("fd467214b4e6468b607f8ca3faa556304491c150a45548a15e392e6bbdcc1a9452f961e947c757c8a013bcad96177d3aaad0dfeb7306f66cf04f957ada1a9d5347276b33b8e93945ae82d0b72a9260f4d27dec8cab7d1a136a368b7c392bd575f1b76da3a8915a31a449f99665f9460176808924dda4e3cc2da9090ad5d11467");
    auto q = LeLe(
            "cdd9c66811037b2c3a50e643a20a3ccf2c1a97f224f6101bfa6634e26c5c0a9833cf0a6877e255cc5af880c51a654863df9b4af8ea01fb41d57f97d3486a7c7aa6801ff6b4515d66c907129860949fc14986d4e74067aa31ab6a27a60edff10d52cc1680e94af53c90197cfb4292adf80c7efdcc27afc9f667eb4214db6df235");
    auto dP = LeLe(
            "cb532bc80401e7e6cc3fa763f5b407c4a5c4ed7b793d274f9e3ee667fd1762a18fc76338ae281eeb1a5833ade7f6bd129a9faed2926420fdc9da49d2d89475acd40556af4d35f2add91359827bf76a83ee065cdbe6b538eca82ee9725882ba6bde29f75a4466f08d73a46c331110e838093702af7f41c30e7282e3249107a277");
    auto dQ = LeLe(
            "2c2a29615f10be32ea951318f206f1fd95ad9a21e4b04310cfff4f0466da92dcdbd08143b6feb25e64df662be99b8280c6bff767544288b2e592b8795fc45dd0b50fcddf235ffffb3f10038d5a643ec49e6d7878d8d4b1caec0a573cbf053e76e48663ae0f2f93077eb48cf95c0399fbcb71c97a681dc78ad83f8885d179d08d");
    auto qInv = LeLe(
            "18d3ffaadc0d7a233677ec26dd5af5a18ca52fe6643bed224715b7d18cde6cd6b6328229aed2683aaa4828668bc2d751ad6e0ad0957be7faa2956e7d0b9098cb4d9d8a89c75d1953478ce9fe7b6c384cbb0a90897724b12468df2dc403d8b9ebadb9392e8686fa58b40897c5869c09688f019580d0202507e6d8014193e09ae2");


    auto test = LeLe("7465737420746573742074657374");
    auto expected = LeLe(
            "03b2e0b8fa817f93f3a3ed4fc916f891aa8a996bd37ac8d499541093134ee66f67715bfd4b55a0f5469446779f8b275e404fa72cfcee24f6b099f94c107b5e814b48eff9704d28b684ca481bf9ffb4583967411310bd72bd52b6a6b47a9fc2b87b9acf62e33d45dbd9f0237f0bdcbb04b10e8843bbbcc6e221969cc3c2b29d418f3b69b3f52780ee00aa06773c747b8582395d2347400c8ceea780a95155fde8c52e2c445cce5bd99060761821cb2914d0220da36adf224dabd1fe9c84ea8fdffcb693dc5cac785bfbaff71dc1fe9482ed25df4f0f6a2e95e703ec27558780a09d54b0cefbbf26471fec8881d70f4d94f8c56bdfab27251de874707916b52212");


    intel::BigNumber P("0xfd467214b4e6468b607f8ca3faa556304491c150a45548a15e392e6bbdcc1a9452f961e947c757c8a013bcad96177d3aaad0dfeb7306f66cf04f957ada1a9d5347276b33b8e93945ae82d0b72a9260f4d27dec8cab7d1a136a368b7c392bd575f1b76da3a8915a31a449f99665f9460176808924dda4e3cc2da9090ad5d11467");//p.value(), p.len());
    intel::BigNumber Q("0xcdd9c66811037b2c3a50e643a20a3ccf2c1a97f224f6101bfa6634e26c5c0a9833cf0a6877e255cc5af880c51a654863df9b4af8ea01fb41d57f97d3486a7c7aa6801ff6b4515d66c907129860949fc14986d4e74067aa31ab6a27a60edff10d52cc1680e94af53c90197cfb4292adf80c7efdcc27afc9f667eb4214db6df235");//q.value(), q.len());
    intel::BigNumber DP("0xcb532bc80401e7e6cc3fa763f5b407c4a5c4ed7b793d274f9e3ee667fd1762a18fc76338ae281eeb1a5833ade7f6bd129a9faed2926420fdc9da49d2d89475acd40556af4d35f2add91359827bf76a83ee065cdbe6b538eca82ee9725882ba6bde29f75a4466f08d73a46c331110e838093702af7f41c30e7282e3249107a277");//dP.value(), dP.len());
    intel::BigNumber DQ("0x2c2a29615f10be32ea951318f206f1fd95ad9a21e4b04310cfff4f0466da92dcdbd08143b6feb25e64df662be99b8280c6bff767544288b2e592b8795fc45dd0b50fcddf235ffffb3f10038d5a643ec49e6d7878d8d4b1caec0a573cbf053e76e48663ae0f2f93077eb48cf95c0399fbcb71c97a681dc78ad83f8885d179d08d");//dQ.value(), dQ.len());
    intel::BigNumber QInv("0x18d3ffaadc0d7a233677ec26dd5af5a18ca52fe6643bed224715b7d18cde6cd6b6328229aed2683aaa4828668bc2d751ad6e0ad0957be7faa2956e7d0b9098cb4d9d8a89c75d1953478ce9fe7b6c384cbb0a90897724b12468df2dc403d8b9ebadb9392e8686fa58b40897c5869c09688f019580d0202507e6d8014193e09ae2"); //qInv.value(), qInv.len());
    intel::BigNumber Test("0x01000000000000000000"); //test.value(), test.len()); // 0x0101010101010101010101010101010101010101010101010101010101010101

    intel::BigNumber *res;

    IppsRSAPrivateKeyState *privState = nullptr;
    Ipp8u *scratchBuffer = nullptr;
    int privBufSize = 0;
    BNU_CHUNK_T *pBuffer;
    jbyteArray out = nullptr;
    int keySize = 0;
    int nsN = 0;
    int cipherTextLen = 0;
    Ipp8u *pCipherText = nullptr;

    if (checkStatus("ippsRSA_GetSizePrivateKeyType2",
                    ippStsNoErr,
                    ippsRSA_GetSizePrivateKeyType2(
                            P.BitSize(),
                            Q.BitSize(),
                            &keySize))) {
        goto exit;
    }

    privState = (IppsRSAPrivateKeyState *) (new Ipp8u[keySize]);
    memset(privState, 0, keySize);

    if (checkStatus("ippsRSA_InitPrivateKeyType2", ippStsNoErr,
                    ippsRSA_InitPrivateKeyType2(
                            P.BitSize(),
                            Q.BitSize(),
                            privState, keySize))) {
        goto exit;
    }


    if (checkStatus("ippsRSA_SetPrivateKeyType2", ippStsNoErr, ippsRSA_SetPrivateKeyType2(
            (IppsBigNumState *) P,
            (IppsBigNumState *) Q,
            (IppsBigNumState *) DP,
            (IppsBigNumState *) DQ,
            (IppsBigNumState *) QInv,
            privState))) {
        goto exit;
    }

    if (checkStatus(

            "ippsRSA_GetBufferSizePrivateKey", ippStsNoErr,
            ippsRSA_GetBufferSizePrivateKey(&privBufSize, privState))) {
        goto exit;
    }


    scratchBuffer = new Ipp8u[privBufSize];

    cipherTextLen = bitSizeInBytes(privState->bitSizeN);
    pCipherText = new Ipp8u[cipherTextLen];
    memset(pCipherText,0,cipherTextLen);

    res = new intel::BigNumber((Ipp32u *) pCipherText, cipherTextLen / 4);

//    if (checkStatus("rsa operation", ippStsNoErr,ippsRSA_Decrypt(Test.State(),res->State(),privState,scratchBuffer))) {
//        goto exit;
//    }


    if (checkStatus("rsa operation", ippStsNoErr, ippsRSA_Opp2(
            Test,
             *res,
            privState, scratchBuffer))) {
        goto exit;
    }


    printBig(res);

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