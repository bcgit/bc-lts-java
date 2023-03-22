package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Compare output of native and java implementations of the same transformations.
 */
public class AesECBConcordanceTest
    extends TestCase
{

    public AesECBConcordanceTest()
    {
    }

    @Test
    public void testECBConcordance()
        throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("ecb"))
            {
                fail("no native ecb and no skip set for it");
                return;
            }
            System.out.println("Skipping ECB native concordance test: " + CryptoServicesRegistrar.hasNativeServices());
            return;
        }

        System.out.println(nativeServices.getVariant() + " " + nativeServices.getBuildDate());

        SecureRandom secureRandom = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {

            for (int t = 0; t < 10000; t++)
            {

                AESEngine javaEngine = new AESEngine();
                AESNativeEngine nativeEngine = new AESNativeEngine();

                int blocks = secureRandom.nextInt(100) + 1;
                byte[] msg = new byte[blocks * 16];
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);


                javaEngine.init(true, keyParameter);
                nativeEngine.init(true, keyParameter);

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

                nativeCT[0] ^=1;

                len = nativeEngine.processBlocks(nativeCT, 0, blocks, nativePT, 0);
                TestCase.assertEquals(len, msg.length);

                TestCase.assertFalse("native PT should not match java PT", Arrays.areEqual(javaPT, nativePT));




            }

        }


    }
}
