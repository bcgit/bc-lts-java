package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CCMJavaAgreementTest extends TestCase
{
    private static final String BCFIPS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";

//    public static void main(
//            String[] args)
//            throws Exception
//    {
//        CCMJavaAgreementTest test = new CCMJavaAgreementTest();
//        test.testInterleavedAAD();
//        test.testCCMSpreadAgreement();
//        test.testCCMJavaAgreement_128();
//        test.testCCMJavaAgreement_192();
//        test.testCCMJavaAgreement_256();
//        System.out.println("Pass the CCMJavaAgreementTest");
//    }

    @Before
    public void setUp()
    {

//        ConsoleHandler consoleHandler = new ConsoleHandler();
//        consoleHandler.setLevel(Level.FINE);
//        Logger foo = Logger.getLogger("org.bouncycastle.util.dispose.DisposalDaemon");
//        foo.setLevel(Level.FINE);
//        foo.addHandler(consoleHandler);
        //  Logger.getLogger("org.bouncycastle.util.dispose.DisposalDaemon").addHandler(consoleHandler);


        String forcedVariant = System.getProperty(BCFIPS_LIB_CPU_VARIANT);
        if (forcedVariant != null)
        {
            String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
            if (variant == null) {
                variant = "java";
            }

            if (!forcedVariant.equals(variant))
            {
                System.out.println("Forced variant not the same as loaded variant: "+forcedVariant + " " + CryptoServicesRegistrar.getNativeServices().getVariant());
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
        CCMModeCipher ccm = CCMBlockCipher.newInstance(AESEngine.newInstance());

        ccm.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", ccm.toString().contains("CCM[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", ccm.toString().contains("CCM[Java]"));
        }


        byte[] out = new byte[ccm.getOutputSize(message.length)];
        int j = ccm.processBytes(message, 0, message.length, out, 0);
        ccm.doFinal(out, j);

        return out;
    }

    byte[] generatePT(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        CCMModeCipher ccm = CCMBlockCipher.newInstance(AESEngine.newInstance());

        ccm.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", ccm.toString().contains("CCM[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", ccm.toString().contains("CCM[Java]"));
        }


        byte[] out = new byte[ccm.getOutputSize(ct.length)];
        int j = ccm.processBytes(ct, 0, ct.length, out, 0);
        ccm.doFinal(out, j);

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

            byte[] iv = new byte[13];
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


        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom secureRandom = new SecureRandom();

        for (int l = 0; l < 5000; l++)
        {


            byte[] key = new byte[16];
            secureRandom.nextBytes(key);

            byte[] iv = new byte[13];
            secureRandom.nextBytes(iv);

            byte[] msg = new byte[l];
            secureRandom.nextBytes(msg);

            byte[] aad = new byte[l];
            secureRandom.nextBytes(aad);

            byte[] nativeCT = new byte[l + 16];
            byte[] javaCT = new byte[l + 16];

            CryptoServicesRegistrar.setNativeEnabled(false);

            {
                CCMModeCipher javaEncryptor = createOutputEncryptor(key, iv, 128);
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
                CCMModeCipher nativeEncryptor = createOutputEncryptor(key, iv, 128);
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
    public void testCCMSpreadAgreement() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Spread Agreement: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            for (int ivLen = 7; ivLen <= 13; ivLen++)
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);


                for (int macSize = 32; macSize <= 128; macSize += 16)
                {

                    for (int msgSize = 0; msgSize < 515; msgSize++)
                    {

                        byte[] msg = new byte[msgSize];
                        rand.nextBytes(msg);

                        CryptoServicesRegistrar.setNativeEnabled(false);
                        CCMModeCipher javaEnc = createOutputEncryptor(key, iv, macSize);
                        CCMModeCipher javaDec = createOutputDecryptor(key, iv, macSize);

                        CryptoServicesRegistrar.setNativeEnabled(true);
                        CCMModeCipher nativeEnc = createOutputEncryptor(key, iv, macSize);
                        CCMModeCipher nativeDec = createOutputDecryptor(key, iv, macSize);

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


    private void writeAllAndClose(byte[] data, ByteArrayOutputStream bos, CCMModeCipher os) throws Exception
    {

        byte[] output = new byte[os.getOutputSize(data.length)];

        int j = 0;
        j = os.processBytes(data, 0, data.length, output, j);

        os.doFinal(output, j);

        bos.write(output);


    }


    @Test
    public void testCCMJavaAgreement_128()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(16);
    }

    @Test
    public void testCCMJavaAgreement_192()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(24);
    }

    @Test
    public void testCCMJavaAgreement_256()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(32);
    }

    /**
     * Feed the output of one call into another without reinitializing the transformation.
     * Compare final result between both platforms.
     */
    @Test
    public void testCascadedTransformation() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
            {
                TestCase.fail("Skipping CCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }

        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        int macSize = 48;

        SecureRandom rand = new SecureRandom();
        rand.nextBytes(key);
        rand.nextBytes(iv);

        byte[] msg = new byte[16];
        rand.nextBytes(msg);

        CryptoServicesRegistrar.setNativeEnabled(false);
        CCMModeCipher javaEnc = createOutputEncryptor(key, iv, macSize);
        CCMModeCipher javaDec = createOutputDecryptor(key, iv, macSize);

        CryptoServicesRegistrar.setNativeEnabled(true);
        CCMModeCipher nativeEnc = createOutputEncryptor(key, iv, macSize);
        CCMModeCipher nativeDec = createOutputDecryptor(key, iv, macSize);

        byte[] javaFeedback = Arrays.clone(msg);
        byte[] nativeFeedback = Arrays.clone(msg);


        //
        // In the encrypt direction
        //
        for (int t = 0; t < 10; t++)
        {
            javaFeedback = javaEnc.processPacket(javaFeedback, 0, javaFeedback.length);
            nativeFeedback = nativeEnc.processPacket(nativeFeedback, 0, nativeFeedback.length);
            TestCase.assertTrue(Arrays.areEqual(nativeFeedback, javaFeedback));
        }


        //
        // In the decrypt direction
        //
        for (int t = 0; t < 10; t++)
        {
            javaFeedback = javaDec.processPacket(javaFeedback, 0, javaFeedback.length);
            nativeFeedback = nativeDec.processPacket(nativeFeedback, 0, nativeFeedback.length);
            TestCase.assertTrue(Arrays.areEqual(nativeFeedback, javaFeedback));
        }

        TestCase.assertTrue(Arrays.areEqual(javaFeedback, msg));
        TestCase.assertTrue(Arrays.areEqual(nativeFeedback, msg));


    }


    private static CCMModeCipher createOutputEncryptor(byte[] key, byte[] iv, int macSize)
    {

        CCMModeCipher c = CCMBlockCipher.newInstance(AESEngine.newInstance());
        c.init(true, new AEADParameters(new KeyParameter(key), macSize, iv));

        return c;
    }


    private static CCMModeCipher createOutputDecryptor(byte[] key, byte[] iv, int macSize)
    {
        CCMModeCipher c = CCMBlockCipher.newInstance(AESEngine.newInstance());
        c.init(false, new AEADParameters(new KeyParameter(key), macSize, iv));

        return c;
    }
}
