package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.junit.Test;

public class NativeFailsafeTest
        extends TestCase
{

    public static final String NATIVE_FAILSAFE_TEST = "test.bcfips.ignore.native";


    /**
     * Test requested variant is loaded if a specific variant is requested.
     */
    @Test
    public void testExpectedVariant()
    {
        String requestedVariant = System.getProperty("org.bouncycastle.native.cpu_variant");
        if (requestedVariant != null)
        {

            CryptoServicesRegistrar.isNativeEnabled();

            NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();

            String variant = nativeServices.getVariant();
            if (variant == null) {
                variant = "java";
            }
            assertTrue("expected variant of " + requestedVariant + " got " + nativeServices.getVariant(), variant.equals(requestedVariant));

        } else
        {
            System.out.println("No expected variant supplied.");
        }
    }

    @Test
    public void testECB()
    {

        boolean hasECB = !NativeLoader.isJavaSupportOnly() &&  NativeFeatures.hasAESHardwareSupport();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasECB)
        {
            if (skip.contains("ecb"))
            {
                return;
            }
            fail("expected support for native ecb");
        }
    }

    @Test
    public void testCBC()
    {

        boolean hasCBC = !NativeLoader.isJavaSupportOnly() && NativeFeatures.hasCBCHardwareSupport();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasCBC)
        {
            if (skip.contains("cbc"))
            {
                return;
            }
            fail("expected support for native cbc");
        }
    }


    @Test
    public void testGCM()
    {

        boolean hasGCM = !NativeLoader.isJavaSupportOnly() && NativeFeatures.hasGCMHardwareSupport();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasGCM)
        {
            if (skip.contains("gcm"))
            {
                return;
            }
            fail("expected support for native gcm");
        }
    }

    @Test
    public void testCTR()
    {

        boolean hasCTR = !NativeLoader.isJavaSupportOnly() && NativeFeatures.hasCTRHardwareSupport();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasCTR)
        {
            if (skip.contains("ctr"))
            {
                return;
            }
            fail("expected support for native gcm");
        }
    }

    @Test
    public void testCFB()
    {

        boolean hasCFB = !NativeLoader.isJavaSupportOnly() && NativeFeatures.hasCFBHardwareSupport();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasCFB)
        {
            if (skip.contains("cfb"))
            {
                return;
            }
            fail("expected support for native gcm");
        }
    }

}
