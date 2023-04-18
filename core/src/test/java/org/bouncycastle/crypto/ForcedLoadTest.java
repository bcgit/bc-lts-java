package org.bouncycastle.crypto;

import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.util.Properties;
import org.junit.Before;
import org.junit.Test;

/**
 * This tests ensures that if a forced library is requested then it matches the loaded library.
 */
public class ForcedLoadTest
{
    @Before
    public void before()
    {

        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    @Test
    public void testForcedVariantIsLoadedVariant()
    {
        if (!CryptoServicesRegistrar.getNativeServices().isInstalled())
        {
            System.out.println("Skipping, no native support.");
            return;
        }


        //
        // Allow test runner to gate-out test if natural lib select is required.
        //
        if (System.getProperty("unforced-variant-test-bypass", "").equals("true"))
        {
            System.out.println("Skipping as test run is not intending to force a native variant");
            return;
        }


        String forcedVariant = Properties.getPropertyValue(NativeLoader.BCFIPS_LIB_CPU_VARIANT);
        if (forcedVariant == null)
        {
            TestCase.fail("no forced variant selected by test runner, if forcing a variant is not intended then set -Dunforced-variant-test-bypass=true");
        }

        TestCase.assertEquals("forced variant and native lib variant did not match", NativeLibIdentity.getLibraryIdent(), forcedVariant);

    }
}
