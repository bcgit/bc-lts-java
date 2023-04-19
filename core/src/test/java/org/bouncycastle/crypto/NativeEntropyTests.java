package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

public class NativeEntropyTests
        extends TestCase
{

    /**
     * To properly validate an entropy source you need
     * to perform a statistical analysis of the output.
     * <p>
     * This test does not do that, it is here to check that it returns something.
     */
    @Test
    public void testESBasic()
            throws Exception
    {

        NativeLoader.loadDriver();

        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG)
            && !CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {

            if (System.getProperty("test.bcfips.ignore.native","").contains("es")) {
                System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
                return;
            }

            TestCase.fail("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());

        }

        NativeEntropySource nes = new NativeEntropySource(1024);
        byte[] entropy1 = nes.getEntropy();
        byte[] entropy2 = nes.getEntropy();

        // Must not be same.
        TestCase.assertFalse(Arrays.areEqual(entropy1, entropy2));

    }

    @Test
    public void testESLimits()
            throws Exception
    {
        NativeLoader.loadDriver();
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG)
                && !CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {

            if (System.getProperty("test.bcfips.ignore.native","").contains("es")) {
                System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
                return;
            }

            TestCase.fail("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
        }


        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG)
            && !CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {
            System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
            return;
        }

        try
        {
            NativeEntropySource nes = new NativeEntropySource(0);
            fail("size un bits less than zero");
        } catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("bit size less than 1"));
        }
    }

    @Test
    public void testLimitsEnforcedFromNative() throws Exception {

        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG)
                && !CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {

            if (System.getProperty("test.bcfips.ignore.native","").contains("es")) {
                System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
                return;
            }

            TestCase.fail("Skipping testLimitsEnforcedFromNative, no native random: " + NativeLoader.getNativeStatusMessage());

        }

        NativeLoader.loadDriver();

        NativeEntropySource es = new NativeEntropySource(128);
        try
        {
            es.seedBuffer(null, true);
            fail("not accept null");
        } catch (Exception ex) {
            TestCase.assertTrue(ex.getMessage().contains("array cannot be null"));
        }

        try
        {
            es.seedBuffer(new byte[1], true);
            fail("not accept null");
        } catch (Exception ex) {
            TestCase.assertTrue(ex.getMessage().contains("array must be multiple of modulus"));
        }
    }

}
