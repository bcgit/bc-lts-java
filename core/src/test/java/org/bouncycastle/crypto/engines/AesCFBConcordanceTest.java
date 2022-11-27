package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Compare output of native and java implementations of the same transformations.
 */
public class AesCFBConcordanceTest
        extends TestCase {
    public AesCFBConcordanceTest() {
    }


    /**
     * Native CFB tries to process data where possible using block size hunks however
     * it will switch to byte by byte if the input is less than one block. This test
     * simulates that by processing one byte first then the remainder of the message.
     * It tests the logic involved in that transition and the same result is observed with the java api.
     *
     * @throws Exception
     */
    public void testCFBByteByByte() throws Exception {

        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CFB")) {
            System.out.println("Skipping CFB native concordance test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        for (int keySize : new int[]{16, 24, 32}) {

            for (int t = 0; t < 10000; t++) {

                MultiBlockCipher javaEngine = new CFBBlockCipher(new AESEngine(), 128);
                AESNativeCFB nativeEngine = new AESNativeCFB(128);

                int blocks = secureRandom.nextInt(100) + 1;
                byte[] msg = new byte[blocks * 16];
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));

                byte[] javaCT = new byte[msg.length];
                byte[] nativeCT = new byte[msg.length];


                int len = javaEngine.processBlocks(msg, 0, blocks, javaCT, 0);
                TestCase.assertEquals(len, msg.length);

                for (int j = 0; j < msg.length; j++) {
                    nativeCT[j] = nativeEngine.returnByte(msg[j]);
                }

                TestCase.assertEquals(len, msg.length);

                // Concordance
                TestCase.assertTrue("native CT matches java CT", Arrays.areEqual(javaCT, nativeCT));

                javaEngine.init(false, keyParameter);
                nativeEngine.init(false, keyParameter);

                byte[] javaPT = new byte[msg.length];
                byte[] nativePT = new byte[msg.length];

                // Concordance

                len = javaEngine.processBlocks(javaCT, 0, blocks, javaPT, 0);
                TestCase.assertEquals(len, msg.length);
                for (int j = 0; j < msg.length; j++) {
                    nativePT[j] = nativeEngine.returnByte(nativeCT[j]);
                }
                TestCase.assertEquals(len, msg.length);

                TestCase.assertTrue("native PT matches java PT", Arrays.areEqual(javaPT, nativePT));
                TestCase.assertTrue("PT matches original message", Arrays.areEqual(javaPT, msg));

                //
                // Discordance, vandalise cipher text on native side
                //

                nativeCT[0] ^= 1;

                len = nativeEngine.processBlocks(nativeCT, 0, blocks, nativePT, 0);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertFalse("native PT should not match java PT", Arrays.areEqual(javaPT, nativePT));


            }


        }

    }


    /**
     * Native CFB tries to process data where possible using block size hunks however
     * it will switch to byte by byte if the input is less than one block. This test
     * simulates that by processing one byte first then the remainder of the message.
     * It tests the logic involved in that transition and the same result is observed with the java api.
     *
     * @throws Exception
     */
    public void testCFBOffsetByte() throws Exception {

        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CFB")) {
            System.out.println("Skipping CFB native concordance test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        for (int keySize : new int[]{16, 24, 32}) {

            for (int t = 0; t < 10000; t++) {

                MultiBlockCipher javaEngine = new CFBBlockCipher(new AESEngine(), 128);
                AESNativeCFB nativeEngine = new AESNativeCFB(128);

                int blocks = secureRandom.nextInt(100) + 1;
                byte[] msg = new byte[blocks * 16];
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));

                byte[] javaCT = new byte[msg.length];
                byte[] nativeCT = new byte[msg.length];


                int len = javaEngine.processBlocks(msg, 0, blocks, javaCT, 0);
                TestCase.assertEquals(len, msg.length);
                len = nativeEngine.processBytes(msg, 0, 1, nativeCT, 0);
                len += nativeEngine.processBytes(msg, len, msg.length - 1, nativeCT, len);
                TestCase.assertEquals(len, msg.length);

                // Concordance
                TestCase.assertTrue("native CT matches java CT", Arrays.areEqual(javaCT, nativeCT));

                javaEngine.init(false, keyParameter);
                nativeEngine.init(false, keyParameter);

                byte[] javaPT = new byte[msg.length];
                byte[] nativePT = new byte[msg.length];

                // Concordance

                len = javaEngine.processBlocks(javaCT, 0, blocks, javaPT, 0);
                TestCase.assertEquals(len, msg.length);
                len = nativeEngine.processBytes(nativeCT, 0, 1, nativePT, 0);
                len += nativeEngine.processBytes(nativeCT, len, nativeCT.length - 1, nativePT, len);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertTrue("native PT matches java PT", Arrays.areEqual(javaPT, nativePT));
                TestCase.assertTrue("PT matches original message", Arrays.areEqual(javaPT, msg));

                //
                // Discordance, vandalise cipher text on native side
                //

                nativeCT[0] ^= 1;

                len = nativeEngine.processBlocks(nativeCT, 0, blocks, nativePT, 0);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertFalse("native PT should not match java PT", Arrays.areEqual(javaPT, nativePT));


            }


        }

    }


    @Test
    public void testCFBConcordance()
            throws Exception {

        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CFB")) {
            System.out.println("Skipping CFB native concordance test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        for (int keySize : new int[]{16, 24, 32}) {

            for (int t = 0; t < 10000; t++) {

                MultiBlockCipher javaEngine = new CFBBlockCipher(new AESEngine(), 128);
                AESNativeCFB nativeEngine = new AESNativeCFB(128);

                int blocks = secureRandom.nextInt(100) + 1;
                byte[] msg = new byte[blocks * 16];
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));

                byte[] javaCT = new byte[msg.length];
                byte[] nativeCT = new byte[msg.length];


                int len = javaEngine.processBlocks(msg, 0, blocks, javaCT, 0);
                TestCase.assertEquals(len, msg.length);
                len = nativeEngine.processBlocks(msg, 0, blocks, nativeCT, 0);
                TestCase.assertEquals(len, msg.length);

                // Concordance
                TestCase.assertTrue("native CT matches java CT", Arrays.areEqual(javaCT, nativeCT));

                javaEngine.init(false, keyParameter);
                nativeEngine.init(false, keyParameter);

                byte[] javaPT = new byte[msg.length];
                byte[] nativePT = new byte[msg.length];

                // Concordance

                len = javaEngine.processBlocks(javaCT, 0, blocks, javaPT, 0);
                TestCase.assertEquals(len, msg.length);
                len = nativeEngine.processBlocks(nativeCT, 0, blocks, nativePT, 0);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertTrue("native PT matches java PT", Arrays.areEqual(javaPT, nativePT));
                TestCase.assertTrue("PT matches original message", Arrays.areEqual(javaPT, msg));

                //
                // Discordance, vandalise cipher text on native side
                //

                nativeCT[0] ^= 1;

                len = nativeEngine.processBlocks(nativeCT, 0, blocks, nativePT, 0);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertFalse("native PT should not match java PT", Arrays.areEqual(javaPT, nativePT));


            }


        }

    }
}
