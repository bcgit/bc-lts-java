package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.junit.Test;

/**
 * The org.bouncycastle.native.rand selection: the RandSource enum, and the two pure resolution
 * helpers on the package-private NativeEntropySource that turn a selection plus the CPU's two
 * features into "can the native entropy source serve this" and "which instruction does it issue".
 * <p>
 * None of these tests touch the hardware. The helpers take the selection and the features as
 * parameters, so every row of the table can be driven on any machine, RDSEED-less hosts and the
 * java control slot included.
 * </p>
 * <p>
 * UNTESTED here, deliberately: a value of org.bouncycastle.native.rand that is not one of
 * RDRAND, RDSEED, AUTO or NONE makes class initialisation of CryptoServicesRegistrar fail. The
 * class is initialised once per JVM and is already initialised by the time a test runs, so the
 * case needs a fresh class loader to reach - the same argument as the retry property, see
 * CryptoServicesRegistrarRNGRetriesTest. The intent is recorded in the javadoc of
 * getNativeRandSource() instead.
 * </p>
 */
public class NativeRandSourceTest
        extends TestCase
{
    /**
     * With the property unset - which is how the test JVMs run - the selection is AUTO.
     */
    @Test
    public void testDefaultSelectionIsAuto()
            throws Exception
    {
        if (Properties.getPropertyValue(Properties.NATIVE_RAND_SOURCE) != null)
        {
            // the property is under test elsewhere; do not assert the default over the top of it
            return;
        }

        TestCase.assertEquals(NativeServices.RandSource.AUTO, DefaultNativeServices.nativeRandSource());
    }

    /**
     * The NativeServices default method is the only way out of this package, so it must report
     * what the internals hold. A downstream implementation that does not override it gets the
     * same answer, which is the point of the method being a default rather than abstract.
     */
    @Test
    public void testInterfaceDefaultReportsTheSelection()
            throws Exception
    {
        NativeServices services = CryptoServicesRegistrar.getNativeServices();

        TestCase.assertEquals(DefaultNativeServices.nativeRandSource(), services.getNativeRandSource());

        NativeServices bare = new NativeServicesStub();

        TestCase.assertEquals(DefaultNativeServices.nativeRandSource(), bare.getNativeRandSource());
        TestCase.assertEquals(DefaultNativeServices.maxRNGRetries(), bare.getMaxRNGRetries());
    }

    /**
     * An implementation that takes both settings from the defaults, as a downstream one would.
     */
    private static class NativeServicesStub
            implements NativeServices
    {
        public String getStatusMessage()
        {
            return "UNSUPPORTED";
        }

        public java.util.Set<String> getFeatureSet()
        {
            return java.util.Collections.singleton(NativeServices.NONE);
        }

        public String getVariant()
        {
            return NativeServices.NONE;
        }

        public String[][] getVariantSelectionMatrix()
        {
            return new String[0][];
        }

        public boolean hasService(String feature)
        {
            return false;
        }

        public String getBuildDate()
        {
            return "";
        }

        public String getLibraryIdent()
        {
            return "";
        }

        public boolean isEnabled()
        {
            return false;
        }

        public boolean isInstalled()
        {
            return false;
        }

        public boolean isSupported()
        {
            return false;
        }
    }

    /**
     * The live helpers must agree with the table for the selection and features this machine
     * actually has, so a wiring mistake between the no-argument and the parameterised forms is
     * caught rather than only the pure table being exercised.
     */
    @Test
    public void testLiveAgreesWithTable()
            throws Exception
    {
        NativeLoader.loadDriver();

        NativeServices.RandSource source = DefaultNativeServices.nativeRandSource();
        boolean hasSeed = NativeLoader.hasNativeService(NativeServices.NRBG);
        boolean hasRand = NativeLoader.hasNativeService(NativeServices.DRBG);

        // a forced selection the CPU cannot serve throws from both forms, so compare the
        // outcome rather than the return value - otherwise the comparison itself would fail
        // on the throwing rows.
        TestCase.assertEquals(describe("isAvailable", source, hasSeed, hasRand),
                outcome(available(source, hasSeed, hasRand)), outcome(available()));

        TestCase.assertEquals(describe("resolveUseSeedSource", source, hasSeed, hasRand),
                outcome(useSeedSource(source, hasSeed, hasRand)), outcome(useSeedSource()));
    }

    private interface Call
    {
        boolean run();
    }

    private Call available(final NativeServices.RandSource source, final boolean hasSeed, final boolean hasRand)
    {
        return new Call()
        {
            public boolean run()
            {
                return NativeEntropySource.isAvailable(source, hasSeed, hasRand);
            }
        };
    }

    private Call available()
    {
        return new Call()
        {
            public boolean run()
            {
                return NativeEntropySource.isAvailable();
            }
        };
    }

    private Call useSeedSource(final NativeServices.RandSource source, final boolean hasSeed, final boolean hasRand)
    {
        return new Call()
        {
            public boolean run()
            {
                return NativeEntropySource.resolveUseSeedSource(source, hasSeed, hasRand);
            }
        };
    }

    private Call useSeedSource()
    {
        return new Call()
        {
            public boolean run()
            {
                return NativeEntropySource.resolveUseSeedSource();
            }
        };
    }

    /**
     * Run a call and describe what came back, the thrown message included, so two calls that are
     * meant to agree can be compared on the throwing rows as well as the returning ones.
     */
    private String outcome(Call call)
    {
        try
        {
            return String.valueOf(call.run());
        }
        catch (IllegalStateException ex)
        {
            return "IllegalStateException: " + ex.getMessage();
        }
    }

    /**
     * The provider the rest of the library actually uses has to hand back a working entropy
     * source, on this machine, with whatever org.bouncycastle.native.rand selects.
     * <p>
     * This is the end-to-end check the table tests above do not make. getDefaultEntropySourceProvider
     * wraps its base provider in OneShotHybridEntropySource (or HybridEntropySource), and that
     * wrapper used to cast the base source to the package-private IncrementalEntropySource - which
     * the native source does not implement. Every call threw ClassCastException on any machine with
     * native DRBG/NRBG, and nothing in the suite noticed, because nothing else calls get() on the
     * default provider. DumpInfo is what surfaced it.
     * </p>
     */
    @Test
    public void testDefaultProviderYieldsUsableEntropy()
            throws Exception
    {
        NativeLoader.loadDriver();

        EntropySource es = CryptoServicesRegistrar.getDefaultEntropySourceProvider().get(256);

        TestCase.assertEquals(256, es.entropySize());

        byte[] first = es.getEntropy();

        TestCase.assertEquals(32, first.length);
        TestCase.assertFalse("entropy source returned all zeroes", allZero(first));

        // a second draw must not repeat the first - a source that cached or returned a constant
        // would pass the length and non-zero checks above
        byte[] second = es.getEntropy();

        TestCase.assertEquals(32, second.length);
        TestCase.assertFalse("entropy source returned all zeroes", allZero(second));
        TestCase.assertFalse("entropy source repeated its output", Arrays.areEqual(first, second));
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
     * Walks every row of the selection table without touching the hardware. The pure helpers take
     * the selection and the two CPU features as parameters, so all sixteen combinations can be
     * driven on any machine.
     */
    @Test
    public void testResolveTable()
            throws Exception
    {
        //
        // AUTO: RDSEED where the CPU has it, otherwise RDRAND, otherwise no native source.
        //
        assertAvailable(NativeServices.RandSource.AUTO, true, true, true);
        assertAvailable(NativeServices.RandSource.AUTO, true, false, true);
        assertAvailable(NativeServices.RandSource.AUTO, false, true, true);
        assertAvailable(NativeServices.RandSource.AUTO, false, false, false);

        assertUseSeedSource(NativeServices.RandSource.AUTO, true, true, true);
        assertUseSeedSource(NativeServices.RandSource.AUTO, true, false, true);
        assertUseSeedSource(NativeServices.RandSource.AUTO, false, true, false);
        assertUseSeedSourceRejected(NativeServices.RandSource.AUTO, false, false,
                "no hardware support for random");

        //
        // RDSEED: forced. Absent with the native layer on is an error, not a fallback.
        //
        assertAvailable(NativeServices.RandSource.RDSEED, true, true, true);
        assertAvailable(NativeServices.RandSource.RDSEED, true, false, true);
        assertAvailableRejected(NativeServices.RandSource.RDSEED, false, true,
                "RDSEED selected but not supported by this CPU");
        // native layer off altogether, the fallback is used
        assertAvailable(NativeServices.RandSource.RDSEED, false, false, false);

        assertUseSeedSource(NativeServices.RandSource.RDSEED, true, true, true);
        assertUseSeedSource(NativeServices.RandSource.RDSEED, true, false, true);
        assertUseSeedSourceRejected(NativeServices.RandSource.RDSEED, false, true,
                "RDSEED selected but not supported by this CPU");
        assertUseSeedSourceRejected(NativeServices.RandSource.RDSEED, false, false,
                "RDSEED selected but not supported by this CPU");

        //
        // RDRAND: forced, also on a CPU that has RDSEED.
        //
        assertAvailable(NativeServices.RandSource.RDRAND, true, true, true);
        assertAvailable(NativeServices.RandSource.RDRAND, false, true, true);
        assertAvailableRejected(NativeServices.RandSource.RDRAND, true, false,
                "RDRAND selected but not supported by this CPU");
        // native layer off altogether, the fallback is used
        assertAvailable(NativeServices.RandSource.RDRAND, false, false, false);

        assertUseSeedSource(NativeServices.RandSource.RDRAND, true, true, false);
        assertUseSeedSource(NativeServices.RandSource.RDRAND, false, true, false);
        assertUseSeedSourceRejected(NativeServices.RandSource.RDRAND, true, false,
                "RDRAND selected but not supported by this CPU");
        assertUseSeedSourceRejected(NativeServices.RandSource.RDRAND, false, false,
                "RDRAND selected but not supported by this CPU");

        //
        // NONE: the fallback, whatever the CPU has.
        //
        assertAvailable(NativeServices.RandSource.NONE, true, true, false);
        assertAvailable(NativeServices.RandSource.NONE, true, false, false);
        assertAvailable(NativeServices.RandSource.NONE, false, true, false);
        assertAvailable(NativeServices.RandSource.NONE, false, false, false);

        assertUseSeedSourceRejected(NativeServices.RandSource.NONE, true, true,
                "org.bouncycastle.native.rand=NONE");
        assertUseSeedSourceRejected(NativeServices.RandSource.NONE, true, false,
                "org.bouncycastle.native.rand=NONE");
        assertUseSeedSourceRejected(NativeServices.RandSource.NONE, false, true,
                "org.bouncycastle.native.rand=NONE");
        assertUseSeedSourceRejected(NativeServices.RandSource.NONE, false, false,
                "org.bouncycastle.native.rand=NONE");
    }

    /**
     * The four names are the contract the property parses against, and the order they are
     * declared in is not. A rename or a reorder that went unnoticed would silently change which
     * values org.bouncycastle.native.rand accepts.
     */
    @Test
    public void testEnumNames()
            throws Exception
    {
        TestCase.assertEquals(4, NativeServices.RandSource.values().length);

        TestCase.assertEquals(NativeServices.RandSource.RDRAND, NativeServices.RandSource.valueOf("RDRAND"));
        TestCase.assertEquals(NativeServices.RandSource.RDSEED, NativeServices.RandSource.valueOf("RDSEED"));
        TestCase.assertEquals(NativeServices.RandSource.AUTO, NativeServices.RandSource.valueOf("AUTO"));
        TestCase.assertEquals(NativeServices.RandSource.NONE, NativeServices.RandSource.valueOf("NONE"));

        // the match is exact - no trimming, no case folding
        assertNotAName("rdseed");
        assertNotAName(" RDSEED");
        assertNotAName("RDSEED ");
        assertNotAName("");
    }

    private void assertNotAName(String value)
    {
        try
        {
            NativeServices.RandSource.valueOf(value);
            fail("\"" + value + "\" should not be a RandSource name");
        }
        catch (IllegalArgumentException ex)
        {
            // expected
        }
    }

    private void assertAvailable(NativeServices.RandSource source, boolean hasSeed, boolean hasRand, boolean expected)
    {
        TestCase.assertEquals(describe("isAvailable", source, hasSeed, hasRand),
                expected, NativeEntropySource.isAvailable(source, hasSeed, hasRand));
    }

    private void assertAvailableRejected(NativeServices.RandSource source, boolean hasSeed, boolean hasRand, String message)
    {
        try
        {
            NativeEntropySource.isAvailable(source, hasSeed, hasRand);
            fail(describe("isAvailable", source, hasSeed, hasRand) + " should have been rejected");
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(describe("isAvailable", source, hasSeed, hasRand) + " message was: " + ex.getMessage(),
                    ex.getMessage().contains(message));
        }
    }

    private void assertUseSeedSource(NativeServices.RandSource source, boolean hasSeed, boolean hasRand, boolean expected)
    {
        TestCase.assertEquals(describe("resolveUseSeedSource", source, hasSeed, hasRand),
                expected, NativeEntropySource.resolveUseSeedSource(source, hasSeed, hasRand));
    }

    private void assertUseSeedSourceRejected(NativeServices.RandSource source, boolean hasSeed, boolean hasRand, String message)
    {
        try
        {
            NativeEntropySource.resolveUseSeedSource(source, hasSeed, hasRand);
            fail(describe("resolveUseSeedSource", source, hasSeed, hasRand) + " should have been rejected");
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(describe("resolveUseSeedSource", source, hasSeed, hasRand) + " message was: " + ex.getMessage(),
                    ex.getMessage().contains(message));
        }
    }

    private String describe(String method, NativeServices.RandSource source, boolean hasSeed, boolean hasRand)
    {
        return method + "(" + source + ", NRBG=" + hasSeed + ", DRBG=" + hasRand + ")";
    }
}
