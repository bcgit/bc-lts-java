package org.bouncycastle.crypto.engines;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Before;
import org.junit.Test;

public class NativeFailsafeTest
{
    public static final String NATIVE_FAILSAFE_TEST = "test.bclts.ignore.native";


    @Before
    public void setUp()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=ecb, etc
     */
    @Test
    public void testAesEcb()
    {

        NativeServices srv = CryptoServicesRegistrar.getNativeServices();

        if (!srv.hasService(NativeServices.AES_ECB))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("ecb"))
            {
                System.out.println("Native ECB skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }
            TestCase.fail("native not supported for AES ECB' and 'test.bclts.ignore.native' does not contain 'ecb'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=cbc, etc
     */
    @Test
    public void testAesCBC()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CBC))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("cbc"))
            {
                System.out.println("Native CBC skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for AES CBC' and 'test.bclts.ignore.native' does not contain 'cbc'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }

    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=gcm, etc
     */
    @Test
    public void testAesGCM()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("gcm"))
            {
                System.out.println("Native GCM skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for AES GCM' and 'test.bclts.ignore.native' does not contain 'gcm'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=ctr, etc
     */
    @Test
    public void testAesCTR()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CTR))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("ctr"))
            {
                System.out.println("Native CTR skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for AES GCM' and 'test.bclts.ignore.native' does not contain 'ctr'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=sha, etc
     */
    @Test
    public void testSHA()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.SHA2))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("sha"))
            {
                System.out.println("Native SHA skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for SHA x' and 'test.bclts.ignore.native' does not contain 'sha'. See README.md  " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }
    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=cfb, etc
     */
    @Test
    public void testAesCFB()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CFB))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("cfb"))
            {
                System.out.println("Native CFB skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for AES CFB' and 'test.bclts.ignore.native' does not contain 'ctr'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=rand, etc
     */
    @Test
    public void testRdRand()
    {

        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("drbg"))
            {
                System.out.println("Native RAND skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for HW Rand' and 'test.bclts.ignore.native' does not contain 'rand'. See README.md  " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


    /**
     * This test will fail if the native libraries cannot be loaded.
     * To disable the test, set NATIVE_FAILSAFE_TEST in the
     * jvmArgs value of the test stanza in the build.gradle
     * <p>
     * -Dtest.bclts.ignore.native=seed, etc
     */
    @Test
    public void testRdSeed()
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {
            if (System.getProperty(NATIVE_FAILSAFE_TEST, "").contains("nrbg"))
            {
                System.out.println("Native SEED skip detected in " + NATIVE_FAILSAFE_TEST + " " + System.getProperty(NATIVE_FAILSAFE_TEST, ""));
                System.out.println("Native Features: " + TestUtil.getNativeFeatureString());
                return;
            }

            TestCase.fail("native not supported for HW Seed' and property 'test.bclts.ignore.native' does not contain 'seed'. See README.md " + CryptoServicesRegistrar.getNativeServices().getStatusMessage());
        }

    }


}
