package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Compare output of native and java implementations of the same transformations.
 */
public class AesGCMConcordanceTest
    extends TestCase
{

    public AesGCMConcordanceTest() {

    }

    @Test
    public void testGCMConcordance()
        throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/GCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("gcm"))
            {
                fail("no native gcm and no skip set for it");
                return;
            }
            System.out.println("Skipping GCM native concordance test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }


        SecureRandom secureRandom = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {

            for (int t = 0; t < 10000; t++)
            {

                GCMBlockCipher javaEngine = new GCMBlockCipher(new AESEngine());
                GCMModeCipher nativeEngine = new AESNativeGCM();

                int bytes = secureRandom.nextInt(65535) + 1;
                byte[] msg = new byte[bytes];
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));

                byte[] javaCT = new byte[javaEngine.getOutputSize(msg.length)];
                byte[] nativeCT = new byte[nativeEngine.getOutputSize(msg.length)];


                int len = javaEngine.processBytes(msg, 0, msg.length, javaCT, 0);
                javaEngine.doFinal(javaCT, len);

                len = nativeEngine.processBytes(msg, 0, msg.length, nativeCT, 0);
                nativeEngine.doFinal(nativeCT, len);

                // Concordance
                TestCase.assertTrue("native CT matches java CT", Arrays.areEqual(javaCT, nativeCT));

                javaEngine.init(false, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(false, new ParametersWithIV(keyParameter, iv));

                byte[] javaPT = new byte[javaEngine.getOutputSize(javaCT.length)];
                byte[] nativePT = new byte[nativeEngine.getOutputSize(nativeCT.length)];

                // Concordance

                len = javaEngine.processBytes(javaCT, 0, javaCT.length, javaPT, 0);
                javaEngine.doFinal(javaPT, len);
                len = nativeEngine.processBytes(nativeCT, 0, nativeCT.length, nativePT, 0);
                nativeEngine.doFinal(nativePT, len);

                TestCase.assertTrue("native PT matches java PT", Arrays.areEqual(javaPT, nativePT));
                TestCase.assertTrue("PT matches original message", Arrays.areEqual(javaPT, msg));


            }

            Runtime.getRuntime().gc();

        }


    }
}
