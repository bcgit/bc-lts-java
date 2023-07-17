package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;


import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.bouncycastle.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class GCMJavaAgreementTest extends TestCase
{
    private static final String BCFIPS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";

    @Before
    public void setUp()
    {
        String forcedVariant = System.getProperty(BCFIPS_LIB_CPU_VARIANT);
        if (forcedVariant != null)
        {

            if (!forcedVariant.equals(CryptoServicesRegistrar.getNativeServices().getLibraryIdent()))
            {
                throw new RuntimeException("Forced variant not the same as loaded variant: " + forcedVariant + " " + CryptoServicesRegistrar.getNativeServices().getVariant());
            }
        }

    }


    @After
    public void tearDown()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    byte[] generateCT(byte[] message, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        GCMModeCipher gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());

        gcm.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", gcm.toString().contains("GCM[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", gcm.toString().contains("GCM[Java]"));
        }


        byte[] out = new byte[gcm.getOutputSize(message.length)];
        int j = gcm.processBytes(message, 0, message.length, out, 0);
        gcm.doFinal(out, j);

        return out;
    }

    byte[] generatePT(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        GCMModeCipher gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());

        gcm.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", gcm.toString().contains("GCM[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", gcm.toString().contains("GCM[Java]"));
        }


        byte[] out = new byte[gcm.getOutputSize(ct.length)];
        int j = gcm.processBytes(ct, 0, ct.length, out, 0);
        gcm.doFinal(out, j);

        return out;

    }

    public void doTest(int keySize)
            throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();


        for (int t = 0; t < 4000; t++)
        {
            byte[] javaPT = new byte[secureRandom.nextInt(2048)];
            secureRandom.nextBytes(javaPT);
            byte[] key = new byte[keySize];
            secureRandom.nextBytes(key);

            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);

            //
            // Generate expected result from Java API.
            //
            CryptoServicesRegistrar.setNativeEnabled(false);
            byte[] javaCT = generateCT(javaPT, key, iv, false);
            TestCase.assertFalse(CryptoServicesRegistrar.getNativeServices().isEnabled());


            //
            // Turn on native
            //
            CryptoServicesRegistrar.setNativeEnabled(true);

            {
                //
                // Original AES-NI not AXV etc
                //
                byte[] ct = generateCT(javaPT, key, iv, true);

                if (!Arrays.areEqual(ct, javaCT))
                {
                    System.out.println(javaPT.length);
                    System.out.println(Hex.toHexString(javaCT));
                    System.out.println(Hex.toHexString(ct));
                    for (int j = 0; j < javaCT.length; j++)
                    {
                        if (javaCT[j] == ct[j])
                        {
                            System.out.print("  ");
                        }
                        else
                        {
                            System.out.print("^^");
                        }
                    }
                    System.out.println();
                }

                TestCase.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

                byte[] pt = generatePT(javaCT, key, iv, true);


                if (!Arrays.areEqual(pt, javaPT))
                {
                    System.out.println(Hex.toHexString(pt));
                    System.out.println(Hex.toHexString(javaPT));
                }


                TestCase.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));
            }

        }

    }

    @Test
    public void testInterleavedAAD() throws Exception
    {


        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom secureRandom = new SecureRandom();

        for (int l = 0; l < 5000; l++)
        {


            byte[] key = new byte[16];
            secureRandom.nextBytes(key);

            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);

            byte[] msg = new byte[l];
            secureRandom.nextBytes(msg);

            byte[] aad = new byte[l];
            secureRandom.nextBytes(aad);

            byte[] nativeCT = new byte[l + 16];
            byte[] javaCT = new byte[l + 16];

            CryptoServicesRegistrar.setNativeEnabled(false);

            {
                GCMModeCipher javaEncryptor = createOutputEncryptor(key, iv, 128);
                TestCase.assertTrue(javaEncryptor.toString().contains("Java"));
                int j = 0;
                for (int t = 0; t < msg.length; t++)
                {
                    j += javaEncryptor.processByte(msg[t], javaCT, j);
                    javaEncryptor.processAADByte(msg[t]);
                }

                javaEncryptor.doFinal(javaCT, j);


            }

            {
                CryptoServicesRegistrar.setNativeEnabled(true);
                GCMModeCipher nativeEncryptor = createOutputEncryptor(key, iv, 128);
                TestCase.assertTrue(nativeEncryptor.toString().contains("Native"));

                int j = 0;
                for (int t = 0; t < msg.length; t++)
                {
                    j += nativeEncryptor.processByte(msg[t], nativeCT, j);
                    nativeEncryptor.processAADByte(msg[t]);
                }

                nativeEncryptor.doFinal(nativeCT, j);
            }


            if (!Arrays.areEqual(nativeCT, javaCT))
            {
                System.out.println("Native: " + Hex.toHexString(nativeCT));
                System.out.println("Java:   " + Hex.toHexString(javaCT));
                TestCase.fail("native CT did not match java CT");
            }
        }

    }

    /**
     * Exercise combinations of key size, iv len and mac len along with increasing msg lengths from zero to 512bytes
     *
     * @throws Exception
     */
    @Test
    public void testGCMSpreadAgreement() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Spread Agreement: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            for (int ivLen = 12; ivLen <= 16; ivLen++)
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);


                for (int macSize = 32; macSize <= 128; macSize += 8)
                {

                    for (int msgSize = 0; msgSize < 515; msgSize++)
                    {

                        byte[] msg = new byte[msgSize];
                        rand.nextBytes(msg);

                        CryptoServicesRegistrar.setNativeEnabled(false);
                        GCMModeCipher javaEnc = createOutputEncryptor(key, iv, macSize);
                        GCMModeCipher javaDec = createOutputDecryptor(key, iv, macSize);

                        CryptoServicesRegistrar.setNativeEnabled(true);
                        GCMModeCipher nativeEnc = createOutputEncryptor(key, iv, macSize);
                        GCMModeCipher nativeDec = createOutputDecryptor(key, iv, macSize);

                        ByteArrayOutputStream javaCt = new ByteArrayOutputStream();
                        writeAllAndClose(msg, javaCt, javaEnc);

                        ByteArrayOutputStream javaPt = new ByteArrayOutputStream();
                        writeAllAndClose(javaCt.toByteArray(), javaPt, javaDec);

                        ByteArrayOutputStream nativeCt = new ByteArrayOutputStream();
                        writeAllAndClose(msg, nativeCt, nativeEnc);


                        if (!Arrays.areEqual(javaCt.toByteArray(), nativeCt.toByteArray()))
                        {
                            System.out.println("Java:   " + Hex.toHexString(javaCt.toByteArray()));
                            System.out.println("Native: " + Hex.toHexString(nativeCt.toByteArray()));
                        }


                        ByteArrayOutputStream nativePt = new ByteArrayOutputStream();
                        writeAllAndClose(nativeCt.toByteArray(), nativePt, nativeDec);

                        TestCase.assertTrue(Arrays.areEqual(nativeCt.toByteArray(), javaCt.toByteArray()));
                        TestCase.assertTrue(Arrays.areEqual(nativePt.toByteArray(), javaPt.toByteArray()));

                        TestCase.assertTrue(Arrays.areEqual(msg, nativePt.toByteArray()));

                    }
                }
            }

        }
    }

    // 36864


    private void writeAllAndClose(byte[] data, ByteArrayOutputStream bos, GCMModeCipher os) throws Exception
    {

        byte[] output = new byte[os.getOutputSize(data.length)];

        int j = 0;
        j = os.processBytes(data, 0, data.length, output, j);

        os.doFinal(output, j);

        bos.write(output);


    }


    @Test
    public void testGCMJavaAgreement_128()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(16);
    }

    @Test
    public void testGCMJavaAgreement_192()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(24);
    }

    @Test
    public void testGCMJavaAgreement_256()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(32);
    }

    private static GCMModeCipher createOutputEncryptor(byte[] key, byte[] iv, int macSize)
    {

        GCMModeCipher c = GCMBlockCipher.newInstance(AESEngine.newInstance());
        c.init(true, new AEADParameters(new KeyParameter(key), macSize, iv));

        return c;
    }


    private static GCMModeCipher createOutputDecryptor(byte[] key, byte[] iv, int macSize)
    {
        GCMModeCipher c = GCMBlockCipher.newInstance(AESEngine.newInstance());
        c.init(false, new AEADParameters(new KeyParameter(key), macSize, iv));

        return c;
    }

}
