package org.bouncycastle.crypto.engines;


import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

public class GCMJavaAgreementTest extends TestCase
{
    private static final String BCFIPS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";

    @BeforeEach
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


    @AfterEach
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
            Assertions.assertTrue(gcm.toString().contains("GCM[Native]"), "Native implementation expected");
        }
        else
        {
            Assertions.assertTrue(gcm.toString().contains("GCM[Java]"), "Java implementation expected");
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
            Assertions.assertTrue(gcm.toString().contains("GCM[Native]"), "Native implementation expected");
        }
        else
        {
            Assertions.assertTrue(gcm.toString().contains("GCM[Java]"), "Java implementation expected");
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
            Assertions.assertFalse(CryptoServicesRegistrar.getNativeServices().isEnabled());


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

                Assertions.assertTrue(Arrays.areEqual(ct, javaCT), keySize + " AES-NI CT did not match");

                byte[] pt = generatePT(javaCT, key, iv, true);


                if (!Arrays.areEqual(pt, javaPT))
                {
                    System.out.println(Hex.toHexString(pt));
                    System.out.println(Hex.toHexString(javaPT));
                }


                Assertions.assertTrue(Arrays.areEqual(pt, javaPT), keySize + " AES-NI PT did not match");
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
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
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
                Assertions.assertTrue(javaEncryptor.toString().contains("Java"));
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
                Assertions.assertTrue(nativeEncryptor.toString().contains("Native"));

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
                Assertions.fail("native CT did not match java CT");
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
                Assertions.fail("Skipping GCM Spread Agreement: " + TestUtil.errorMsg());
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
                        try
                        {
                            writeAllAndClose(nativeCt.toByteArray(), nativePt, nativeDec);

                        }
                        catch (Exception ex)
                        {

                            System.out.println(Hex.toHexString(key));
                            System.out.println(Hex.toHexString(iv));

                            System.out.println(Hex.toHexString(nativeCt.toByteArray()));
                            System.out.println(Hex.toHexString(javaCt.toByteArray()));

                            System.out.println(Hex.toHexString(msg));

                            throw ex;
                        }

                        Assertions.assertTrue(Arrays.areEqual(nativeCt.toByteArray(), javaCt.toByteArray()), "cipher text");

                        if (!Arrays.areEqual(javaPt.toByteArray(), nativePt.toByteArray()))
                        {
                            System.out.println("Java:   " + Hex.toHexString(javaPt.toByteArray()));
                            System.out.println("Native: " + Hex.toHexString(nativePt.toByteArray()));
                        }

                        Assertions.assertTrue(Arrays.areEqual(nativePt.toByteArray(), javaPt.toByteArray()), "plain text");

                        Assertions.assertTrue(Arrays.areEqual(msg, nativePt.toByteArray()));

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
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
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
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
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
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(32);
    }

    private static void fillCount(byte[] out)
    {
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte) i;
        }
    }

    @Test
    public void testPartialUpdates_4() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        String var = CryptoServicesRegistrar.getNativeServices().getVariant();

        boolean correctVariant = "vaes".equals(var) || "avx".equals(var) || "neon-le".equals(var);

       if (!correctVariant) {
           System.out.println("Skipping testPartialUpdates_4 Agreement Test: incorrect variant " + var);
           return;
       }

        byte[] key = new byte[16];
        fillCount(key);

        byte[] iv = new byte[12];
        fillCount(iv);

        byte[] message = new byte[2045];
        fillCount(message);

        GCMModeCipher gcmEncrypt = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcmEncrypt.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] ciperText = new byte[message.length + 16];

        int i = gcmEncrypt.processBytes(message, 0, message.length, ciperText, 0);
        gcmEncrypt.doFinal(ciperText, i);

        byte[] plainText = new byte[message.length];


        //
        // Verify correct decryption without exception
        //

        GCMModeCipher gcmDecryptOneShot = GCMBlockCipher.newInstance(AESEngine.newInstance());

        Assertions.assertEquals(AESNativeGCM.class, gcmDecryptOneShot.getClass());

        gcmDecryptOneShot.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        i = gcmDecryptOneShot.processBytes(ciperText, 0, ciperText.length, plainText, 0);
        gcmDecryptOneShot.doFinal(plainText, i);

        Assertions.assertTrue(Arrays.areEqual(plainText, message));

        GCMModeCipher gcmDecrypt = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcmDecrypt.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        i = 0;
        int p = 0;
        int remaining = ciperText.length;


        for (int t = 0; t < 16 * 4 - 1; t++)
        {
            i += gcmDecrypt.processBytes(ciperText, p, 1, plainText, i);
            p += 1;
            remaining -= 1;
        }


        i += gcmDecrypt.processBytes(ciperText, p, 7, plainText, i);
        p += 7;
        remaining -= 7;

        i += gcmDecrypt.processBytes(ciperText, p, remaining, plainText, i);
        gcmDecrypt.doFinal(plainText, i);

        Assertions.assertTrue(Arrays.areEqual(plainText, message));

    }


    @Test
    public void testPartialUpdates_16() throws Exception
    {


        if (!TestUtil.hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                Assertions.fail("Skipping GCM Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }

        if (!"vaesf".equals(CryptoServicesRegistrar.getNativeServices().getVariant()))
        {
            System.out.println("Skipping testPartialUpdates_16 Agreement Test: incorrect variant " + CryptoServicesRegistrar.getNativeServices().getVariant());
            return;
        }


        byte[] key = new byte[16];
        fillCount(key);

        byte[] iv = new byte[12];
        fillCount(iv);

        byte[] message = new byte[2045];
        fillCount(message);

        GCMModeCipher gcmEncrypt = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcmEncrypt.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] ciperText = new byte[message.length + 16];

        int i = gcmEncrypt.processBytes(message, 0, message.length, ciperText, 0);
        gcmEncrypt.doFinal(ciperText, i);

        byte[] plainText = new byte[message.length];


        //
        // Verify correct decryption without exception
        //

        GCMModeCipher gcmDecryptOneShot = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcmDecryptOneShot.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        i = gcmDecryptOneShot.processBytes(ciperText, 0, ciperText.length, plainText, 0);
        gcmDecryptOneShot.doFinal(plainText, i);

        Assertions.assertTrue(Arrays.areEqual(plainText, message));

        GCMModeCipher gcmDecrypt = GCMBlockCipher.newInstance(AESEngine.newInstance());
        gcmDecrypt.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        i = 0;
        int p = 0;
        int remaining = ciperText.length;


        for (int t = 0; t < 16 * 17 - 1; t++)
        {
            i += gcmDecrypt.processBytes(ciperText, p, 1, plainText, i);
            p += 1;
            remaining -= 1;
        }


        i += gcmDecrypt.processBytes(ciperText, p, 7, plainText, i);
        p += 7;
        remaining -= 7;

        i += gcmDecrypt.processBytes(ciperText, p, remaining, plainText, i);
        gcmDecrypt.doFinal(plainText, i);

        Assertions.assertTrue(Arrays.areEqual(plainText, message));

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
