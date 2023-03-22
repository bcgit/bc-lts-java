package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
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

    public AesGCMConcordanceTest()
    {

    }




    @Test
    public void testGCMConcordanceOverRangeByteByByte()
            throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasService("AES/GCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("gcm"))
            {
                fail("no native gcm and no skip set for it");
                return;
            }
            System.out.println("Skipping GCM native concordance test: " + CryptoServicesRegistrar.hasNativeServices());
            return;
        }

        System.out.println(NativeServices.getVariant() + " " + NativeServices.getBuildDate());

        SecureRandom secureRandom = new SecureRandom();


        byte[] aad =  new byte[2048];
        secureRandom.nextBytes(aad);



        for (int keySize : new int[]{16, 24, 32})
        {

            for (int t = 0; t < 2048; t++)
            {

                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);
                GCMBlockCipher javaEngine = new GCMBlockCipher(new AESEngine());
                GCMModeCipher nativeEngine = new AESNativeGCM();

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));


                byte[] msg = new byte[t];
                byte[] javaCT = new byte[javaEngine.getOutputSize(msg.length)];
                byte[] nativeCT = new byte[nativeEngine.getOutputSize(msg.length)];


                int len = 0;
                for (int j = 0; j < msg.length; j++)
                {
                    len += javaEngine.processByte(msg[j], javaCT, len);
                    javaEngine.processAADByte(aad[j]);
                }
                javaEngine.doFinal(javaCT,len);



                len = 0;
                for (int j = 0; j < msg.length; j++)
                {
                    len += nativeEngine.processByte(msg[j], nativeCT, len);
                    nativeEngine.processAADByte(aad[j]);
                }


                //     len = nativeEngine.processBytes(msg, 0, msg.length, nativeCT, 0);
                nativeEngine.doFinal(nativeCT, len);

                // Concordance
                TestCase.assertTrue("native CT matches java CT", Arrays.areEqual(javaCT, nativeCT));


                javaEngine.init(false, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(false, new ParametersWithIV(keyParameter, iv));

                byte[] javaPT = new byte[javaEngine.getOutputSize(javaCT.length)];
                byte[] nativePT = new byte[nativeEngine.getOutputSize(nativeCT.length)];

                // Concordance


                len = 0;
                for (int j = 0; j < javaCT.length; j++)
                {
                    len += javaEngine.processByte(javaCT[j], javaPT, len);
                    if (j < msg.length)
                    {
                        javaEngine.processAADByte(aad[j]);
                    }
                }
                javaEngine.doFinal(javaPT, len);


                len = 0;
                for (int j = 0; j < nativeCT.length; j++)
                {
                    len += nativeEngine.processByte(nativeCT[j], nativePT, len);
                    if (j < msg.length)
                    {
                        nativeEngine.processAADByte(aad[j]);
                    }
                }
                nativeEngine.doFinal(nativePT, len);

                TestCase.assertTrue("native PT matches java PT", Arrays.areEqual(javaPT, nativePT));
                TestCase.assertTrue("PT matches original message", Arrays.areEqual(javaPT, msg));


            }

            Runtime.getRuntime().gc();

        }


    }


    @Test
    public void testGCMConcordanceOverRange()
            throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasService("AES/GCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("gcm"))
            {
                fail("no native gcm and no skip set for it");
                return;
            }
            System.out.println("Skipping GCM native concordance test: " + CryptoServicesRegistrar.hasNativeServices());
            return;
        }

        System.out.println(NativeServices.getVariant() + " " + NativeServices.getBuildDate());

        SecureRandom secureRandom = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {


            for (int t = 0; t < 10000; t++)
            {

                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);
                KeyParameter keyParameter = new KeyParameter(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);
                GCMBlockCipher javaEngine = new GCMBlockCipher(new AESEngine());
                GCMModeCipher nativeEngine = new AESNativeGCM();

                javaEngine.init(true, new ParametersWithIV(keyParameter, iv));
                nativeEngine.init(true, new ParametersWithIV(keyParameter, iv));


                int bytes = t;

                byte[] msg = new byte[bytes];
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


    @Test
    public void testGCMConcordance()
            throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasService("AES/GCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("gcm"))
            {
                fail("no native gcm and no skip set for it");
                return;
            }
            System.out.println("Skipping GCM native concordance test: " + CryptoServicesRegistrar.hasNativeServices());
            return;
        }

        System.out.println(NativeServices.getVariant() + " " + NativeServices.getBuildDate());

        SecureRandom secureRandom = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {

            for (int t = 0; t < 10000; t++)
            {

                GCMBlockCipher javaEngine = new GCMBlockCipher(new AESEngine());
                GCMModeCipher nativeEngine = new AESNativeGCM();

                int bytes = secureRandom.nextInt(1024) + 1;
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
