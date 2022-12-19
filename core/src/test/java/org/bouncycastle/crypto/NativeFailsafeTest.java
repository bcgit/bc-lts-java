package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.bouncycastle.crypto.NativeLoader;
import org.junit.Test;

import static junit.framework.TestCase.fail;

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

            CryptoServicesRegistrar.getNativeStatus();
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

        boolean hasECB = NativeLoader.hasHardwareAesECB();

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

        boolean hasCBC = NativeLoader.hasHardwareAesCBC();

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

        boolean hasGCM = NativeLoader.hasHardwareAesGCM();

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
