package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Compare output of native and java implementations of the same transformations.
 */
public class AesCBCConcordanceTest
    extends TestCase
{

    public AesCBCConcordanceTest()
    {

    }

    @Test
    public void testCBCConcordance()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CBC"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cbc and no skip set for it");
                return;
            }
            System.out.println("Skipping CBC native concordance test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        System.out.println(NativeServices.getVariant() + " " + NativeServices.getBuildDate());


        SecureRandom secureRandom = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {


            for (int t = 0; t < 10000; t++)
            {

                MultiBlockCipher javaEngine = new CBCBlockCipher(new AESEngine());
                AESNativeCBC nativeEngine = new AESNativeCBC();

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

                TestCase.assertTrue("native PT matches java PT "+keySize+" "+msg.length, Arrays.areEqual(javaPT, nativePT));
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
