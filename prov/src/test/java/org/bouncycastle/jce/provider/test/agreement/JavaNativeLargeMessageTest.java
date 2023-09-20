package org.bouncycastle.jce.provider.test.agreement;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class JavaNativeLargeMessageTest extends SimpleTest
{


    private static final int largeMSG = 1024 * 1024 * 151;

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


    @Override
    public String getName()
    {
        return "Java-Native Large Message Test";
    }

    @Test
    public void testGCMJavaLargeAgreement() throws Exception
    {

        if (!hasNativeService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("gcm"))
            {
                TestCase.fail("Skipping GCM Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        int macSize = 128;


        byte[] iv = new byte[12];
        rand.nextBytes(iv);

        AEADParameterSpec ivSpec = new AEADParameterSpec(iv, macSize);

        int msgSize = 1 + largeMSG;
        byte[] msg = new byte[msgSize];
        rand.nextBytes(msg);


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
                TestCase.assertTrue(getEngineString(gcmDecJava).contains("AES[Java"));
                TestCase.assertTrue(getEngineString(gcmEncJava).contains("AES[Java"));
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
                TestCase.assertTrue(getEngineString(gcmDecNative).contains("AES[Native"));
                TestCase.assertTrue(getEngineString(gcmEncNative).contains("AES[Native"));
            }

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


    @Test
    public void testCTRJavaLargeAgreement() throws Exception
    {

        if (!hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        int macSize = 128;


        byte[] iv = new byte[8];
        rand.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        int msgSize = 1 + largeMSG;
        byte[] msg = new byte[msgSize];
        rand.nextBytes(msg);


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            SecretKeySpec spec = new SecretKeySpec(key, "AES");


            CryptoServicesRegistrar.setNativeEnabled(false);
            Cipher gcmEncJava = Cipher.getInstance("AES/CTR/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecJava = Cipher.getInstance("AES/CTR/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecJava).contains("SICBlockCipher"));
                TestCase.assertTrue(getEngineString(gcmEncJava).contains("SICBlockCipher"));
            }

            CryptoServicesRegistrar.setNativeEnabled(true);
            Cipher gcmEncNative = Cipher.getInstance("AES/CTR/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecNative = Cipher.getInstance("AES/CTR/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecNative).contains("CTR[Native"));
                TestCase.assertTrue(getEngineString(gcmEncNative).contains("CTR[Native"));
            }

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


    @Test
    public void testCFBJavaLargeAgreement() throws Exception
    {

        if (!hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
            {
                TestCase.fail("Skipping CFB Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();




        byte[] iv = new byte[16];
        rand.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        int msgSize = largeMSG +1;
        byte[] msg = new byte[msgSize];
        rand.nextBytes(msg);


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            SecretKeySpec spec = new SecretKeySpec(key, "AES");


            CryptoServicesRegistrar.setNativeEnabled(false);
            Cipher gcmEncJava = Cipher.getInstance("AES/CFB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecJava = Cipher.getInstance("AES/CFB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecJava).contains("CFB[Java"));
                TestCase.assertTrue(getEngineString(gcmEncJava).contains("CFB[Java"));
            }

            CryptoServicesRegistrar.setNativeEnabled(true);
            Cipher gcmEncNative = Cipher.getInstance("AES/CFB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecNative = Cipher.getInstance("AES/CFB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecNative).contains("CFB[Native"));
                TestCase.assertTrue(getEngineString(gcmEncNative).contains("CFB[Native"));
            }

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


    @Test
    public void testCBCJavaLargeAgreement() throws Exception
    {

        if (!hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();




        byte[] iv = new byte[16];
        rand.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        int msgSize =  largeMSG;
        byte[] msg = new byte[msgSize];
        rand.nextBytes(msg);


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            SecretKeySpec spec = new SecretKeySpec(key, "AES");


            CryptoServicesRegistrar.setNativeEnabled(false);
            Cipher gcmEncJava = Cipher.getInstance("AES/CBC/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncJava.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecJava = Cipher.getInstance("AES/CBC/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecJava.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecJava).contains("CBC[Java"));
                TestCase.assertTrue(getEngineString(gcmEncJava).contains("CBC[Java"));
            }
            CryptoServicesRegistrar.setNativeEnabled(true);
            Cipher gcmEncNative = Cipher.getInstance("AES/CBC/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncNative.init(Cipher.ENCRYPT_MODE, spec, ivSpec);

            Cipher gcmDecNative = Cipher.getInstance("AES/CBC/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecNative.init(Cipher.DECRYPT_MODE, spec, ivSpec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecNative).contains("CBC[Native"));
                TestCase.assertTrue(getEngineString(gcmEncNative).contains("CBC[Native"));
            }

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


    @Test
    public void testECBJavaLargeAgreement() throws Exception
    {

        if (!hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Agreement Test: " + errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();


        int msgSize =  largeMSG;
        byte[] msg = new byte[msgSize];
        rand.nextBytes(msg);


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            SecretKeySpec spec = new SecretKeySpec(key, "AES");


            CryptoServicesRegistrar.setNativeEnabled(false);
            Cipher gcmEncJava = Cipher.getInstance("AES/ECB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncJava.init(Cipher.ENCRYPT_MODE, spec);

            Cipher gcmDecJava = Cipher.getInstance("AES/ECB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecJava.init(Cipher.DECRYPT_MODE, spec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecJava).contains("AES[Java"));
                TestCase.assertTrue(getEngineString(gcmEncJava).contains("AES[Java"));
            }

            CryptoServicesRegistrar.setNativeEnabled(true);
            Cipher gcmEncNative = Cipher.getInstance("AES/ECB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmEncNative.init(Cipher.ENCRYPT_MODE, spec);

            Cipher gcmDecNative = Cipher.getInstance("AES/ECB/NoPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            gcmDecNative.init(Cipher.DECRYPT_MODE, spec);

            if (isJava8())
            {
                TestCase.assertTrue(getEngineString(gcmDecNative).contains("AES[Native"));
                TestCase.assertTrue(getEngineString(gcmEncNative).contains("AES[Native"));
            }

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


    @Override
    public void performTest() throws Exception
    {
        testGCMJavaLargeAgreement();
        testCTRJavaLargeAgreement();
        testCFBJavaLargeAgreement();
        testCBCJavaLargeAgreement();
        testECBJavaLargeAgreement();
    }


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

    void moreBytes(byte[] src, SHA256Digest digest)
    {
        digest.update(src, 0, src.length);
        digest.doFinal(src, 0);
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




}
