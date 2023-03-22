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

            CryptoServicesRegistrar.hasNativeServices();
            String variant = NativeServices.getVariant();
            if (variant == null) {
                variant = "java";
            }
            assertTrue("expected variant of " + requestedVariant + " got " + NativeServices.getVariant(), variant.equals(requestedVariant));

        } else
        {
            System.out.println("No expected variant supplied.");
        }
    }

    @Test
    public void testECB()
    {

        boolean hasECB = NativeFeatures.hasAESHardwareSupport();

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

        boolean hasCBC = NativeFeatures.hasCBCHardwareSupport();

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

        boolean hasGCM = NativeFeatures.hasGCMHardwareSupport();

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

}
