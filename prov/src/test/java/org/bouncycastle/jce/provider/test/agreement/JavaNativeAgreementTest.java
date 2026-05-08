package org.bouncycastle.jce.provider.test.agreement;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Field;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class JavaNativeAgreementTest extends TestCase
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

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }


    }


    @After
    public void tearDown()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    @Test
    public void testGCMJavaAgreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        if (!hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();


        for (int macSize = 32; macSize <= 128; macSize += 8)
        {
            for (int ivLen = 12; ivLen <= 16; ivLen++)
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);

                AEADParameterSpec ivSpec = new AEADParameterSpec(iv, macSize);

                for (int msgSize = 0; msgSize < 1023; msgSize++)
                {

                    for (int ks : new int[]{16, 24, 32})
                    {
                        byte[] key = new byte[ks];
                        rand.nextBytes(key);

                        SecretKeySpec spec = new SecretKeySpec(key, "AES");


                        CryptoServicesRegistrar.setNativeEnabled(false);
                        Cipher gcmEncJava = Cipher.getInstance("AES/GCM/NoPadding",
                                BouncyCastleProvider.PROVIDER_NAME);
                        gcmEncJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                        Cipher gcmDecJava = Cipher.getInstance("AES/GCM/NoPadding",
                                BouncyCastleProvider.PROVIDER_NAME);
                        gcmDecJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                        if (isJava8())
                        {
                            TestCase.assertTrue(getEngineString(gcmDecJava).contains("GCM[Java"));
                            TestCase.assertTrue(getEngineString(gcmEncJava).contains("GCM[Java"));
                        }

                        CryptoServicesRegistrar.setNativeEnabled(true);
                        Cipher gcmEncNative = Cipher.getInstance("AES/GCM/NoPadding",
                                BouncyCastleProvider.PROVIDER_NAME);
                        gcmEncNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                        Cipher gcmDecNative = Cipher.getInstance("AES/GCM/NoPadding",
                                BouncyCastleProvider.PROVIDER_NAME);
                        gcmDecNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                        if (isJava8())
                        {
                            TestCase.assertTrue(getEngineString(gcmDecNative).contains("GCM[Native"));
                            TestCase.assertTrue(getEngineString(gcmEncNative).contains("GCM[Native"));
                        }


                        byte[] msg = new byte[msgSize];
                        rand.nextBytes(msg);


                        ByteArrayOutputStream jCtext = new ByteArrayOutputStream();
                        CipherOutputStream javaCos = new CipherOutputStream(jCtext, gcmEncJava);
                        javaCos.write(msg);
                        javaCos.flush();
                        javaCos.close();

                        byte[] javaCt = jCtext.toByteArray();


                        ByteArrayInputStream javaSrc = new ByteArrayInputStream(javaCt);
                        CipherInputStream javaCin = new CipherInputStream(javaSrc, gcmDecJava);

                        byte[] javaPt = Streams.readAll(javaCin);


                        javaCin.close();


                        // Native

                        ByteArrayOutputStream nCtext = new ByteArrayOutputStream();
                        CipherOutputStream nativeCos = new CipherOutputStream(nCtext, gcmEncNative);
                        nativeCos.write(msg);
                        nativeCos.flush();
                        nativeCos.close();

                        byte[] nativeCt = nCtext.toByteArray();


                        ByteArrayInputStream nativeSrc = new ByteArrayInputStream(nativeCt);
                        CipherInputStream nativeCin = new CipherInputStream(nativeSrc, gcmDecNative);

                        byte[] nativePt = Streams.readAll(nativeCin);

                        nativeCin.close();


                        TestCase.assertTrue(Arrays.areEqual(nativePt, msg));
                        TestCase.assertTrue(Arrays.areEqual(nativePt, javaPt));
                        TestCase.assertTrue(Arrays.areEqual(nativeCt, javaCt));

                    }
                }
            }
        }


    }


    @Test
    public void testCTRJavaAgreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        if (!hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int ivLen = 8; ivLen <= 16; ivLen++)
        {
            byte[] iv = new byte[ivLen];
            rand.nextBytes(iv);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            for (int msgSize = 0; msgSize < 513; msgSize++)
            {

                for (int ks : new int[]{16, 24, 32})
                {
                    byte[] key = new byte[ks];
                    rand.nextBytes(key);

                    SecretKeySpec spec = new SecretKeySpec(key, "AES");

                    CryptoServicesRegistrar.setNativeEnabled(false);
                    Cipher ctrEncJava = Cipher.getInstance("AES/CTR/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    ctrEncJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher ctrDecJava = Cipher.getInstance("AES/CTR/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    ctrDecJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(ctrDecJava).contains("SICBlockCipher"));
                        TestCase.assertTrue(getEngineString(ctrEncJava).contains("SICBlockCipher"));
                    }
                    CryptoServicesRegistrar.setNativeEnabled(true);
                    Cipher ctrEncNative = Cipher.getInstance("AES/CTR/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    ctrEncNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher ctrDecNative = Cipher.getInstance("AES/CTR/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    ctrDecNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(ctrDecNative).contains("CTR[Native"));
                        TestCase.assertTrue(getEngineString(ctrEncNative).contains("CTR[Native"));
                    }

                    byte[] msg = new byte[msgSize];
                    rand.nextBytes(msg);


                    ByteArrayOutputStream jCtext = new ByteArrayOutputStream();
                    CipherOutputStream javaCos = new CipherOutputStream(jCtext, ctrEncJava);
                    javaCos.write(msg);
                    javaCos.flush();
                    javaCos.close();

                    byte[] javaCt = jCtext.toByteArray();


                    ByteArrayInputStream javaSrc = new ByteArrayInputStream(javaCt);
                    CipherInputStream javaCin = new CipherInputStream(javaSrc, ctrDecJava);

                    byte[] javaPt = Streams.readAll(javaCin);


                    javaCin.close();


                    // Native

                    ByteArrayOutputStream nCtext = new ByteArrayOutputStream();
                    CipherOutputStream nativeCos = new CipherOutputStream(nCtext, ctrEncNative);
                    nativeCos.write(msg);
                    nativeCos.flush();
                    nativeCos.close();

                    byte[] nativeCt = nCtext.toByteArray();


                    ByteArrayInputStream nativeSrc = new ByteArrayInputStream(nativeCt);
                    CipherInputStream nativeCin = new CipherInputStream(nativeSrc, ctrDecNative);

                    byte[] nativePt = Streams.readAll(nativeCin);


                    // System.out.println(l);
                    nativeCin.close();

                    TestCase.assertTrue(Arrays.areEqual(nativePt, msg));
                    TestCase.assertTrue(Arrays.areEqual(nativePt, javaPt));
                    TestCase.assertTrue(Arrays.areEqual(nativeCt, javaCt));

                }
            }
        }
    }


    @Test
    public void testCFBJavaAgreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        if (!hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
            {
                TestCase.fail("Skipping CFB Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();


        int ivLen = 16;
        {
            byte[] iv = new byte[ivLen];
            rand.nextBytes(iv);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            for (int msgSize = 0; msgSize < 513; msgSize++)
            {

                for (int ks : new int[]{16, 24, 32})
                {
                    byte[] key = new byte[ks];
                    rand.nextBytes(key);

                    SecretKeySpec spec = new SecretKeySpec(key, "AES");

                    CryptoServicesRegistrar.setNativeEnabled(false);
                    Cipher encJava = Cipher.getInstance("AES/CFB/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    encJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher decJava = Cipher.getInstance("AES/CFB/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    decJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(decJava).contains("CFB[Java"));
                        TestCase.assertTrue(getEngineString(encJava).contains("CFB[Java"));
                    }

                    CryptoServicesRegistrar.setNativeEnabled(true);
                    Cipher encNative = Cipher.getInstance("AES/CFB/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    encNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher decNative = Cipher.getInstance("AES/CFB/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    decNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(decNative).contains("CFB[Native"));
                        TestCase.assertTrue(getEngineString(encNative).contains("CFB[Native"));
                    }

                    byte[] msg = new byte[msgSize];
                    rand.nextBytes(msg);


                    ByteArrayOutputStream jCtext = new ByteArrayOutputStream();
                    CipherOutputStream javaCos = new CipherOutputStream(jCtext, encJava);
                    javaCos.write(msg);
                    javaCos.flush();
                    javaCos.close();

                    byte[] javaCt = jCtext.toByteArray();


                    ByteArrayInputStream javaSrc = new ByteArrayInputStream(javaCt);
                    CipherInputStream javaCin = new CipherInputStream(javaSrc, decJava);

                    byte[] javaPt = Streams.readAll(javaCin);


                    javaCin.close();


                    // Native

                    ByteArrayOutputStream nCtext = new ByteArrayOutputStream();
                    CipherOutputStream nativeCos = new CipherOutputStream(nCtext, encNative);
                    nativeCos.write(msg);
                    nativeCos.flush();
                    nativeCos.close();

                    byte[] nativeCt = nCtext.toByteArray();


                    ByteArrayInputStream nativeSrc = new ByteArrayInputStream(nativeCt);
                    CipherInputStream nativeCin = new CipherInputStream(nativeSrc, decNative);

                    byte[] nativePt = Streams.readAll(nativeCin);


                    // System.out.println(l);
                    nativeCin.close();

                    TestCase.assertTrue(Arrays.areEqual(nativePt, msg));
                    TestCase.assertTrue(Arrays.areEqual(nativePt, javaPt));
                    TestCase.assertTrue(Arrays.areEqual(nativeCt, javaCt));

                }
            }
        }
    }


    @Test
    public void testCBCJavaAgreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);

        if (!hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();


        int ivLen = 16;
        {
            byte[] iv = new byte[ivLen];
            rand.nextBytes(iv);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            for (int msgSize = 0; msgSize < 1024; msgSize += 16) // Block cipher only
            {

                for (int ks : new int[]{16, 24, 32})
                {
                    byte[] key = new byte[ks];
                    rand.nextBytes(key);

                    SecretKeySpec spec = new SecretKeySpec(key, "AES");

                    CryptoServicesRegistrar.setNativeEnabled(false);
                    Cipher encJava = Cipher.getInstance("AES/CBC/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    encJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher decJava = Cipher.getInstance("AES/CBC/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    decJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(decJava).contains("CBC[Java"));
                        TestCase.assertTrue(getEngineString(encJava).contains("CBC[Java"));
                    }

                    CryptoServicesRegistrar.setNativeEnabled(true);
                    Cipher encNative = Cipher.getInstance("AES/CBC/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    encNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

                    Cipher decNative = Cipher.getInstance("AES/CBC/NoPadding",
                            BouncyCastleProvider.PROVIDER_NAME);
                    decNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

                    if (isJava8())
                    {
                        TestCase.assertTrue(getEngineString(decNative).contains("CBC[Native"));
                        TestCase.assertTrue(getEngineString(encNative).contains("CBC[Native"));
                    }

                    byte[] msg = new byte[msgSize];
                    rand.nextBytes(msg);


                    ByteArrayOutputStream jCtext = new ByteArrayOutputStream();
                    CipherOutputStream javaCos = new CipherOutputStream(jCtext, encJava);
                    javaCos.write(msg);
                    javaCos.flush();
                    javaCos.close();

                    byte[] javaCt = jCtext.toByteArray();


                    ByteArrayInputStream javaSrc = new ByteArrayInputStream(javaCt);
                    CipherInputStream javaCin = new CipherInputStream(javaSrc, decJava);

                    byte[] javaPt = Streams.readAll(javaCin);


                    javaCin.close();


                    // Native

                    ByteArrayOutputStream nCtext = new ByteArrayOutputStream();
                    CipherOutputStream nativeCos = new CipherOutputStream(nCtext, encNative);
                    nativeCos.write(msg);
                    nativeCos.flush();
                    nativeCos.close();

                    byte[] nativeCt = nCtext.toByteArray();


                    ByteArrayInputStream nativeSrc = new ByteArrayInputStream(nativeCt);
                    CipherInputStream nativeCin = new CipherInputStream(nativeSrc, decNative);

                    byte[] nativePt = Streams.readAll(nativeCin);


                    // System.out.println(l);
                    nativeCin.close();

                    TestCase.assertTrue(Arrays.areEqual(nativePt, msg));
                    TestCase.assertTrue(Arrays.areEqual(nativePt, javaPt));
                    TestCase.assertTrue(Arrays.areEqual(nativeCt, javaCt));

                }
            }
        }


    }


    @Test
    public void testECBJavaAgreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        if (!hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int msgSize = 0; msgSize < 1024; msgSize += 16) // Block cipher only
        {

            for (int ks : new int[]{16, 24, 32})
            {
                byte[] key = new byte[ks];
                rand.nextBytes(key);

                SecretKeySpec spec = new SecretKeySpec(key, "AES");

                CryptoServicesRegistrar.setNativeEnabled(false);
                Cipher encJava = Cipher.getInstance("AES/ECB/NoPadding",
                        BouncyCastleProvider.PROVIDER_NAME);
                encJava.init(Cipher.ENCRYPT_MODE, spec);

                Cipher decJava = Cipher.getInstance("AES/ECB/NoPadding",
                        BouncyCastleProvider.PROVIDER_NAME);
                decJava.init(Cipher.DECRYPT_MODE, spec);

                if (isJava8())
                {
                    TestCase.assertTrue(getEngineString(decJava).contains("AES[Java"));
                    TestCase.assertTrue(getEngineString(encJava).contains("AES[Java"));
                }

                CryptoServicesRegistrar.setNativeEnabled(true);
                Cipher encNative = Cipher.getInstance("AES/ECB/NoPadding",
                        BouncyCastleProvider.PROVIDER_NAME);
                encNative.init(Cipher.ENCRYPT_MODE, spec);

                Cipher decNative = Cipher.getInstance("AES/ECB/NoPadding",
                        BouncyCastleProvider.PROVIDER_NAME);
                decNative.init(Cipher.DECRYPT_MODE, spec);

                if (isJava8())
                {
                    TestCase.assertTrue(getEngineString(decNative).contains("AES[Native"));
                    TestCase.assertTrue(getEngineString(encNative).contains("AES[Native"));
                }

                byte[] msg = new byte[msgSize];
                rand.nextBytes(msg);


                ByteArrayOutputStream jCtext = new ByteArrayOutputStream();
                CipherOutputStream javaCos = new CipherOutputStream(jCtext, encJava);
                javaCos.write(msg);
                javaCos.flush();
                javaCos.close();

                byte[] javaCt = jCtext.toByteArray();


                ByteArrayInputStream javaSrc = new ByteArrayInputStream(javaCt);
                CipherInputStream javaCin = new CipherInputStream(javaSrc, decJava);

                byte[] javaPt = Streams.readAll(javaCin);


                javaCin.close();


                // Native

                ByteArrayOutputStream nCtext = new ByteArrayOutputStream();
                CipherOutputStream nativeCos = new CipherOutputStream(nCtext, encNative);
                nativeCos.write(msg);
                nativeCos.flush();
                nativeCos.close();

                byte[] nativeCt = nCtext.toByteArray();


                ByteArrayInputStream nativeSrc = new ByteArrayInputStream(nativeCt);
                CipherInputStream nativeCin = new CipherInputStream(nativeSrc, decNative);

                byte[] nativePt = Streams.readAll(nativeCin);


                // System.out.println(l);
                nativeCin.close();

                TestCase.assertTrue(Arrays.areEqual(nativePt, msg));
                TestCase.assertTrue(Arrays.areEqual(nativePt, javaPt));
                TestCase.assertTrue(Arrays.areEqual(nativeCt, javaCt));

            }
        }
    }


    @Test
    public void testSHA256Agreement() throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        if (!hasNativeService("SHA2"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();
        for (int msgSize = 0; msgSize < 65537; msgSize++)
        {

            byte[] msg = new byte[msgSize];
            rand.nextBytes(msg);

            byte[] javaDigest = null;
            byte[] nativeDigest = null;


            {
                CryptoServicesRegistrar.setNativeEnabled(false);
                MessageDigest mdJava = MessageDigest.getInstance("SHA256", BouncyCastleProvider.PROVIDER_NAME);

                if (isJava8())
                {
                    TestCase.assertTrue(getDigestEngineString(mdJava).contains("SHA256[Java]"));
                }

                DigestInputStream din = new DigestInputStream(new ByteArrayInputStream(msg), mdJava);
                Streams.drain(din);

                javaDigest = din.getMessageDigest().digest();
            }

            {
                CryptoServicesRegistrar.setNativeEnabled(true);
                MessageDigest mdNative = MessageDigest.getInstance("SHA256", BouncyCastleProvider.PROVIDER_NAME);

                if (isJava8())
                {
                    TestCase.assertTrue(getDigestEngineString(mdNative).contains("SHA256[Native]"));
                }

                DigestInputStream din = new DigestInputStream(new ByteArrayInputStream(msg), mdNative);
                Streams.drain(din);
                nativeDigest = din.getMessageDigest().digest();
            }

            TestCase.assertTrue(Arrays.areEqual(nativeDigest, javaDigest));


        }
    }


    @Test
    public void testForceChunkAgreement() throws Exception
    {
        if (!CryptoServicesRegistrar.hasEnabledService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: testForceChunkAgreement");
            }
            return;
        }

        CryptoServicesRegistrar.setNativeEnabled(true);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        for (int size = 1; size < 16000; size++)
        {
            byte[] data = new byte[size];
            random.nextBytes(data);

            Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            encCipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] encryptedData = encCipher.doFinal(data);

            Cipher singleShotCipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            singleShotCipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] singleShotPt = singleShotCipher.doFinal(encryptedData);
            TestCase.assertTrue("single-shot decrypt mismatch at size " + size,
                    Arrays.areEqual(data, singleShotPt));

            Cipher streamCipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            streamCipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            ByteArrayInputStream bis = new ByteArrayInputStream(encryptedData);
            ForceInputStream fis = new ForceInputStream(bis);
            CipherInputStream cis = new CipherInputStream(fis, streamCipher);
            try
            {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                int n;
                while ((n = cis.read(buf)) != -1)
                {
                    bos.write(buf, 0, n);
                }
                TestCase.assertTrue("force-chunk decrypt mismatch at size " + size,
                        Arrays.areEqual(data, bos.toByteArray()));
            }
            finally
            {
                cis.close();
            }
        }
    }


    private static class ForceInputStream extends FilterInputStream
    {
        private int it = 0;

        ForceInputStream(InputStream in)
        {
            super(in);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            it++;
            if (it == 16)
            {
                len = 487;
            }
            else if (it == 17)
            {
                len = 94;
            }
            return super.read(b, off, len);
        }
    }


    /**
     * Method for getting the toString() value of the baseEngine.
     * This exists to assert that the provider has served up a native or a java only implementation
     * of a given transformation.
     *
     * @param cipher
     * @return
     * @throws Exception
     */
    public String getEngineString(Cipher cipher) throws Exception
    {
        //
        // This will only work on BC LTS.
        //
        Field f = cipher.getClass().getDeclaredField("spi");
        f.setAccessible(true);
        Object spi = f.get(cipher);
        f = spi.getClass().getSuperclass().getDeclaredField("cipher");
        f.setAccessible(true);
        spi = f.get(spi);
        f = spi.getClass().getDeclaredField("cipher");
        f.setAccessible(true);
        spi = f.get(spi);
        return spi.toString();
    }

    /**
     * Method for getting the toString() value of the digest.
     * This exists to assert that the provider has served up a native or a java only implementation
     * of a given transformation.
     *
     * @param cipher
     * @return
     * @throws Exception
     */
    public String getDigestEngineString(MessageDigest cipher) throws Exception
    {
        //
        // This will only work on BC LTS.
        //
        Field f = cipher.getClass().getSuperclass().getDeclaredField("digest");
        f.setAccessible(true);
        Object spi = f.get(cipher);
        return spi.toString();
    }


    @Override
    public String getName()
    {
        return "Java-Native Agreement tests";
    }

//    @Override
//    public void performTest() throws Exception
//    {
//        testCBCJavaAgreement();
//        testCFBJavaAgreement();
//        testCTRJavaAgreement();
//        testECBJavaAgreement();
//        testGCMJavaAgreement();
//        testSHA256Agreement();
//    }

    public static boolean hasNativeService(String service)
    {
        return CryptoServicesRegistrar.hasEnabledService(service);
    }

    public static String errorMsg()
    {
        return getNativeFeatureString();
    }

    public static String getNativeFeatureString()
    {
        return String.join(" ", CryptoServicesRegistrar.getNativeServices().getFeatureSet());
    }

    public static boolean isJava8()
    {
        return System.getProperty("java.version", "").startsWith("1.8");
    }


}
