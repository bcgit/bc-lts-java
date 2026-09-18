package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Boundary / limit test for the hardware-RNG native bridge (native_c/intel/jni/rand_jni.c,
 * surfaced through the package-private NativeEntropySource). The bridge is stateless: there is
 * no native ref to make or dispose as the symmetric ciphers have.
 * <p>
 * The bridge validates its input in this order, and the order is what decides which exception a
 * call with two bad arguments reports:
 * </p>
 * <ol>
 * <li>buf == null -&gt; NullPointerException("array cannot be null")</li>
 * <li>buf.length % 8 != 0 -&gt; IllegalArgumentException("array must be multiple of modulus")</li>
 * <li>maxRetries &lt; 0 -&gt; IllegalArgumentException("maxRetries cannot be negative")</li>
 * <li>the CPU lacks RDSEED / RDRAND -&gt; IllegalStateException("... is not supported by this CPU")</li>
 * </ol>
 * <p>
 * maxRetries bounds the hardware instruction: one attempt then up to maxRetries more, per 64-bit
 * word, with 0 meaning retry without limit. It arrives from
 * DefaultNativeServices.maxRNGRetries().
 * </p>
 * <p>
 * UNTESTABLE from a java test, recorded here so a reader does not read the absent coverage as an
 * oversight:
 * </p>
 * <ul>
 * <li>IllegalStateException("unable to obtain ptr to valid array"): the JVM does not let a test
 * hand a bad array across the JNI boundary.</li>
 * <li>IllegalStateException("RDSEED / RDRAND is not supported by this CPU"): the service is only
 * wired where the probe reports the instruction, so a host that registers DRBG or NRBG cannot
 * reach it, and a host that does not registers no service and skips these tests.</li>
 * <li>IllegalStateException("... persistently failed to produce entropy"): this needs a real
 * hardware failure to provoke. The retry budget that leads to it is covered on the reject side
 * instead, by the negative-maxRetries tests below.</li>
 * </ul>
 */
public class NativeEntropyLimitTest
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

            if (System.getProperty("test.bclts.ignore.native","").contains("es")) {
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

            if (System.getProperty("test.bclts.ignore.native","").contains("es")) {
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

            if (System.getProperty("test.bclts.ignore.native","").contains("es")) {
                System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getNativeStatusMessage());
                return;
            }

            TestCase.fail("Skipping testLimitsEnforcedFromNative, no native random: " + NativeLoader.getNativeStatusMessage());

        }

        NativeLoader.loadDriver();

        NativeEntropySource es = new NativeEntropySource(128);
        try
        {
            es.seedBuffer(null, true, DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES);
            fail("not accept null");
        } catch (Exception ex) {
            TestCase.assertTrue(ex.getMessage().contains("array cannot be null"));
        }

        try
        {
            es.seedBuffer(new byte[1], true, DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES);
            fail("not accept null");
        } catch (Exception ex) {
            TestCase.assertTrue(ex.getMessage().contains("array must be multiple of modulus"));
        }
    }


    /**
     * Return true where this machine has no native random, in which case the caller must not
     * run the native part of its test. Matches the guard the tests above use: a missing native
     * random is a failure unless the "es" token is in test.bclts.ignore.native.
     */
    private boolean skipGuard(String testName)
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.DRBG)
                && !CryptoServicesRegistrar.hasEnabledService(NativeServices.NRBG))
        {

            if (System.getProperty("test.bclts.ignore.native", "").contains("es")) {
                System.out.println("Skipping " + testName + ", no native random: " + NativeLoader.getNativeStatusMessage());
                return true;
            }

            TestCase.fail("Skipping " + testName + ", no native random: " + NativeLoader.getNativeStatusMessage());

        }

        return false;
    }

    /**
     * Return the seed source flag that matches this machine and the org.bouncycastle.native.rand
     * selection, which is the same flag the entropy source itself passes to seedBuffer. The
     * resolution table it delegates to is covered exhaustively by NativeRandSourceTest.
     */
    private boolean useSeedSource()
    {
        return NativeEntropySource.resolveUseSeedSource();
    }

    private static boolean allZero(byte[] buf)
    {
        int bits = 0;
        for (int i = 0; i != buf.length; i++)
        {
            bits |= buf[i];
        }
        return bits == 0;
    }

    /**
     * BOUNDARY RULE: maxRetries must be 0 or greater, where 0 selects retry without limit.
     * -1 is the smallest rejected value, which is what proves the comparison sits at 0 and not
     * at some other constant. -2 is probed as well, and Integer.MIN_VALUE because it survives
     * negation and Math.abs, and because it is the value that becomes huge-but-positive if the
     * sign check is ever moved after the cast to uint64_t on the native side.
     * <p>
     * The useSeed flag must not change the outcome. The native sign check sits before the
     * RDSEED / RDRAND capability gate, so a CPU without RDSEED must still report
     * IllegalArgumentException here rather than IllegalStateException. That assertion is what
     * pins the order of the two checks.
     * </p>
     */
    @Test
    public void testNegativeMaxRetriesRejectedFromNative()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testNegativeMaxRetriesRejectedFromNative"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(128);

        int[] badRetries = new int[]{-1, -2, Integer.MIN_VALUE};
        boolean[] useSeedValues = new boolean[]{false, true};

        for (int i = 0; i != badRetries.length; i++)
        {
            for (int j = 0; j != useSeedValues.length; j++)
            {
                try
                {
                    es.seedBuffer(new byte[8], useSeedValues[j], badRetries[i]);
                    fail("accepted negative maxRetries " + badRetries[i]
                            + " (useSeed=" + useSeedValues[j] + ")");
                }
                catch (IllegalArgumentException ex)
                {
                    TestCase.assertTrue("unexpected message: " + ex.getMessage(),
                            ex.getMessage().contains("maxRetries cannot be negative"));
                }
            }
        }
    }

    /**
     * A negative maxRetries must be rejected before the buffer is touched. The bridge writes the
     * zero-fill only after validation, so a sentinel-filled buffer must come back untouched
     * rather than cleared. This is the same "no partial output alongside the exception" rule the
     * symmetric bridges follow.
     */
    @Test
    public void testNegativeMaxRetriesLeavesBufferAlone()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testNegativeMaxRetriesLeavesBufferAlone"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(128);

        byte[] buf = new byte[16];
        java.util.Arrays.fill(buf, (byte)0xA5);

        try
        {
            es.seedBuffer(buf, false, -1);
            fail("accepted negative maxRetries");
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("maxRetries cannot be negative"));
        }

        for (int i = 0; i != buf.length; i++)
        {
            TestCase.assertEquals("buffer was modified at index " + i + " despite the rejection",
                    (byte)0xA5, buf[i]);
        }
    }

    /**
     * ACCEPT side of the same bound: a budget of 0 (retry without limit) and the shipped default
     * are both in range and must fill the buffer. 64 bytes drives the fill loop over 8 words, so
     * a budget that is consumed once and never reset shows up here.
     */
    @Test
    public void testMaxRetriesAcceptSide()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testMaxRetriesAcceptSide"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(512);

        int[] goodRetries = new int[]{0, DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES};

        for (int i = 0; i != goodRetries.length; i++)
        {
            byte[] buf = new byte[64];
            es.seedBuffer(buf, useSeedSource(), goodRetries[i]);
            TestCase.assertFalse("buffer not filled with maxRetries=" + goodRetries[i], allZero(buf));
        }
    }

    /**
     * A budget of 1 is the smallest bounded one, and it must be ACCEPTED - the check the native
     * side makes is maxRetries &lt; 0, so 1 has to travel the fill loop rather than be rejected
     * out of range.
     * <p>
     * It must not be asserted to SUCCEED. One retry over a 64-byte buffer is 8 words at two
     * attempts each, and RDSEED declines far more often than that: Intel's DRNG guide recommends
     * a baseline of 100 retries for RDSEED against 10 for RDRAND, which is why the shipped
     * default is 1000. A run that exhausts the budget is the source behaving as specified, so
     * both outcomes are correct here and only a third one - a rejection, or any other exception -
     * is a defect. The success path of the fill loop is covered by the two in-range budgets above
     * and by testZeroMaxRetriesSpinsUntilSuccess.
     * </p>
     */
    @Test
    public void testMinimumBoundedBudgetIsAccepted()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testMinimumBoundedBudgetIsAccepted"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(512);

        byte[] buf = new byte[64];

        try
        {
            es.seedBuffer(buf, useSeedSource(), 1);

            TestCase.assertFalse("buffer not filled although seedBuffer returned", allZero(buf));
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue("unexpected message: " + ex.getMessage(),
                    ex.getMessage().contains("persistently failed to produce entropy"));

            // the budget was exhausted, and the contract is that nothing partial is handed back
            TestCase.assertTrue("buffer left partly filled after the budget was exhausted", allZero(buf));
        }
    }

    /**
     * A maxRetries of zero means retry without limit. The buffer must still be filled.
     */
    @Test
    public void testZeroMaxRetriesSpinsUntilSuccess()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testZeroMaxRetriesSpinsUntilSuccess"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(512);

        byte[] buf = new byte[64];
        es.seedBuffer(buf, useSeedSource(), 0);

        TestCase.assertFalse("buffer must not be all zeroes", allZero(buf));
    }

    /**
     * Exercises getEntropy() either side of a retry limit change.
     * <p>
     * Both legs of this test lean on the hardware to deliver entropy, so it can be unreliable on
     * a machine whose hardware RNG is marginal: heavily loaded, under a hypervisor that traps the
     * instruction, or an errata-affected part.
     * </p>
     * <ul>
     * <li>the 1000 leg throws IllegalStateException if the instruction fails 1000 times in a row
     * for one 64-bit word;</li>
     * <li>the 0 leg means retry without limit, so on hardware that never succeeds it does not
     * fail, it hangs. Expect a timeout rather than a red test.</li>
     * </ul>
     * <p>
     * If this test is intermittent, suspect the host before the code. The retry plumbing on the
     * java side is covered without the hardware by CryptoServicesRegistrarRNGRetriesTest.
     * </p>
     */
    @Test
    public void testEntropyWithChangedMaxRNGRetries()
            throws Exception
    {
        NativeLoader.loadDriver();

        if (skipGuard("testEntropyWithChangedMaxRNGRetries"))
        {
            return;
        }

        NativeEntropySource es = new NativeEntropySource(256);

        try
        {
            DefaultNativeServices.setMaxRNGRetries(1000);

            byte[] entropy = es.getEntropy();
            TestCase.assertFalse(allZero(entropy));

            // retry without limit must still produce entropy
            DefaultNativeServices.setMaxRNGRetries(0);

            entropy = es.getEntropy();
            TestCase.assertFalse(allZero(entropy));
        }
        finally
        {
            DefaultNativeServices.setMaxRNGRetries(DefaultNativeServices.DEFAULT_MAX_RNG_RETRIES);
        }
    }

}
