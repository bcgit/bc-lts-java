package org.bouncycastle.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.junit.Test;

/**
 * The java half of the hardware-RNG retry budget: the default, the getter and the setter on
 * CryptoServicesRegistrar. None of these tests touch the native code, so they run on every
 * slot, the java control included.
 * <p>
 * The native half of the bound, and the effect of the budget on getEntropy(), are covered by
 * NativeEntropyLimitTest, which needs the package-private NativeEntropySource and real
 * hardware.
 * </p>
 * <p>
 * UNTESTED here, deliberately: a value of org.bouncycastle.native.rand.max_retries that is not
 * an integer of 0 or greater makes class initialisation of CryptoServicesRegistrar fail. The
 * class is initialised once for each JVM and it is already initialised by the time a test runs,
 * so the case needs a fresh class loader to reach. That harness costs more than the behaviour is
 * worth. The intent is recorded in the javadoc of getMaxRNGRetries() instead.
 * </p>
 */
public class CryptoServicesRegistrarRNGRetriesTest
        extends TestCase
{

    /**
     * The shipped default is 200, and a fresh registrar reports it.
     */
    @Test
    public void testDefaultMaxRNGRetries()
            throws Exception
    {
        TestCase.assertEquals(200, CryptoServicesRegistrar.DEFAULT_MAX_RNG_RETRIES);
        TestCase.assertEquals(CryptoServicesRegistrar.DEFAULT_MAX_RNG_RETRIES,
                CryptoServicesRegistrar.getMaxRNGRetries());
    }

    /**
     * A set is visible to the getter, and 0 is a valid setting because it selects retry
     * without limit.
     */
    @Test
    public void testSetMaxRNGRetries()
            throws Exception
    {
        try
        {
            CryptoServicesRegistrar.setMaxRNGRetries(1000);
            TestCase.assertEquals(1000, CryptoServicesRegistrar.getMaxRNGRetries());

            // zero is valid, it selects retry without limit
            CryptoServicesRegistrar.setMaxRNGRetries(0);
            TestCase.assertEquals(0, CryptoServicesRegistrar.getMaxRNGRetries());
        }
        finally
        {
            CryptoServicesRegistrar.setMaxRNGRetries(CryptoServicesRegistrar.DEFAULT_MAX_RNG_RETRIES);
        }

        TestCase.assertEquals(CryptoServicesRegistrar.DEFAULT_MAX_RNG_RETRIES,
                CryptoServicesRegistrar.getMaxRNGRetries());
    }

    /**
     * A negative value is rejected, and the rejected set must leave the current value alone.
     */
    @Test
    public void testSetMaxRNGRetriesRejectsNegative()
            throws Exception
    {
        try
        {
            CryptoServicesRegistrar.setMaxRNGRetries(-1);
            fail("not accept negative maxRetries");
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue("unexpected message: " + ex.getMessage(),
                    ex.getMessage().contains("cannot be negative"));
        }

        TestCase.assertEquals(CryptoServicesRegistrar.DEFAULT_MAX_RNG_RETRIES,
                CryptoServicesRegistrar.getMaxRNGRetries());
    }
}
