package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * The java half of the hardware-RNG retry budget: the default, the getter and the internal setter
 * on DefaultNativeServices. None of these tests touch the native code, so they run on every slot,
 * the java control included.
 * <p>
 * The native half of the bound, and the effect of the budget on getEntropy(), are covered by
 * NativeEntropyLimitTest, which needs the package-private NativeEntropySource and real hardware.
 * The instruction selection that sits alongside the budget is covered by NativeRandSourceTest.
 * </p>
 * <p>
 * UNTESTED here, deliberately: a value of org.bouncycastle.native.rand.max_retries that is not
 * an integer of 0 or greater makes class initialisation of DefaultNativeServices fail. The class
 * is initialised once for each JVM and it is already initialised by the time a test runs, so the
 * case needs a fresh class loader to reach. That harness costs more than the behaviour is worth.
 * The intent is recorded in the javadoc of getMaxRNGRetries() instead.
 * </p>
 */
public class NativeRNGRetriesTest
        extends TestCase
{
    /**
     * The shipped default is 1000, and a fresh JVM reports it.
     * <p>
     * The literal is the point: it fails if the default moves without the move being intended.
     * </p>
     */
    @Test
    public void testDefaultMaxRNGRetries()
            throws Exception
    {
        TestCase.assertEquals(1000, DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES);
        TestCase.assertEquals(DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES,
                DefaultNativeServices.maxRNGRetries());
    }

    /**
     * The budget is only reachable outside this package through the NativeServices default
     * method, so that must track a set rather than snapshotting at construction.
     */
    @Test
    public void testInterfaceDefaultTracksTheSetting()
            throws Exception
    {
        NativeServices services = CryptoServicesRegistrar.getNativeServices();
        int original = DefaultNativeServices.maxRNGRetries();

        try
        {
            DefaultNativeServices.setMaxRNGRetries(37);
            TestCase.assertEquals(37, services.getMaxRNGRetries());
        }
        finally
        {
            DefaultNativeServices.setMaxRNGRetries(original);
        }

        TestCase.assertEquals(original, services.getMaxRNGRetries());
    }

    /**
     * A set is visible to the getter, and 0 is a valid setting because it selects retry
     * without limit.
     */
    @Test
    public void testSetMaxRNGRetries()
            throws Exception
    {
        int original = DefaultNativeServices.maxRNGRetries();

        try
        {
            // deliberately not the default, so the set is distinguishable from a no-op
            DefaultNativeServices.setMaxRNGRetries(37);
            TestCase.assertEquals(37, DefaultNativeServices.maxRNGRetries());

            // zero is valid, it selects retry without limit
            DefaultNativeServices.setMaxRNGRetries(0);
            TestCase.assertEquals(0, DefaultNativeServices.maxRNGRetries());
        }
        finally
        {
            DefaultNativeServices.setMaxRNGRetries(original);
        }

        TestCase.assertEquals(original, DefaultNativeServices.maxRNGRetries());
    }

    /**
     * A negative value is rejected, and the rejected set must leave the current value alone.
     */
    @Test
    public void testSetMaxRNGRetriesRejectsNegative()
            throws Exception
    {
        int original = DefaultNativeServices.maxRNGRetries();

        try
        {
            DefaultNativeServices.setMaxRNGRetries(-1);
            fail("not accept negative maxRetries");
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue("unexpected message: " + ex.getMessage(),
                    ex.getMessage().contains("cannot be negative"));
        }

        TestCase.assertEquals(original, DefaultNativeServices.maxRNGRetries());
    }

    /**
     * Integer.MIN_VALUE is still negative after a sign flip, so a check written with Math.abs
     * would let it through and the native side would take a huge budget.
     */
    @Test
    public void testSetMaxRNGRetriesRejectsMinValue()
            throws Exception
    {
        int original = DefaultNativeServices.maxRNGRetries();

        try
        {
            DefaultNativeServices.setMaxRNGRetries(Integer.MIN_VALUE);
            fail("not accept Integer.MIN_VALUE maxRetries");
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue("unexpected message: " + ex.getMessage(),
                    ex.getMessage().contains("cannot be negative"));
        }

        TestCase.assertEquals(original, DefaultNativeServices.maxRNGRetries());
    }
}
