package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Reuse of an AES GMAC without a fresh nonce: doFinal twice, reset then doFinal, new data after a
 * doFinal, and re-initialisation with the same or a new IV.
 * <p>
 * Each sequence runs through the lightweight GMac over the java GCM, the lightweight GMac over
 * the default GCM (native where the native layer is loaded), and the JCE "AESGMAC" Mac from the
 * BC provider. Every step must end the same way on all three: the same tag, or the same exception
 * type. Running the test with -Dorg.bouncycastle.native.cpu_variant set to java, avx and vaes then
 * shows the native and java hosts behave identically.
 * </p>
 * <p>
 * Whatever reuse is allowed, a second tag under the same key and nonce over different data must
 * never be produced: two such tags give away the GHASH key.
 * </p>
 */
public class GMacReuseTest
    extends TestCase
{
    // GMacTest 128/96/128/128
    private static final byte[] KEY = Hex.decode("77be63708971c4e240d1cb79e8d77feb");
    private static final byte[] IV = Hex.decode("e0e00f19fed7ba0136a797f3");
    private static final byte[] AD = Hex.decode("7a43ec1d9c0a5a78a0b16533a6213cab");
    private static final byte[] TAG = Hex.decode("209fcc8d3675ed938e9c7166709dd946");

    private static final byte[] IV2 = Hex.decode("000102030405060708090a0b");
    private static final byte[] AD2 = Hex.decode("7a43ec1d9c0a5a78a0b16533a6213cac");

    private static final String TAG_PREFIX = "tag:";

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The anchor: one doFinal on a freshly initialised MAC gives the KAT tag everywhere, and a one
     * bit change in the data changes it.
     */
    public void testSingleUse()
        throws Exception
    {
        GMacOps[] ops = allOps();
        for (int i = 0; i != ops.length; i++)
        {
            ops[i].init(KEY, IV);
            ops[i].update(AD);
            assertTrue(ops[i].name(), Arrays.areEqual(TAG, ops[i].doFinal()));

            ops[i].init(KEY, IV2);
            ops[i].update(AD);
            byte[] t1 = ops[i].doFinal();
            ops[i].init(KEY, IV);
            ops[i].update(AD2);
            byte[] t2 = ops[i].doFinal();
            assertFalse(ops[i].name(), Arrays.areEqual(TAG, t1));
            assertFalse(ops[i].name(), Arrays.areEqual(TAG, t2));
        }
    }

    /**
     * Same key, nonce and data with no re-init: recomputing the tag gives away nothing, so the
     * same tag comes back, however the data is chunked.
     */
    public void testDoFinalTwiceSameData()
        throws Exception
    {
        List<String> outcome = runSequence("doFinal twice, same data", new Sequence()
        {
            public void run(GMacOps m, List<String> out)
            {
                m.init(KEY, IV);
                step(out, m, AD);
                step(out, m, AD);
                stepByteByByte(out, m, AD);
            }
        });

        assertEquals(tags(TAG, TAG, TAG), outcome);
    }

    public void testResetThenDoFinal()
        throws Exception
    {
        List<String> outcome = runSequence("doFinal, reset, doFinal, same data", new Sequence()
        {
            public void run(GMacOps m, List<String> out)
            {
                m.init(KEY, IV);
                step(out, m, AD);
                m.reset();
                step(out, m, AD);
            }
        });

        assertEquals(tags(TAG, TAG), outcome);
    }

    /**
     * A reset before any tag has been produced: nothing has been given out under the nonce yet,
     * so the data that follows gets its tag.
     */
    public void testResetBeforeDoFinal()
        throws Exception
    {
        List<String> outcome = runSequence("update, reset, doFinal", new Sequence()
        {
            public void run(GMacOps m, List<String> out)
            {
                m.init(KEY, IV);
                m.update(AD2);
                m.reset();
                step(out, m, AD);
            }
        });

        assertEquals(tags(TAG), outcome);
    }

    /**
     * Same key and nonce over different data must not produce a tag. It is refused with the
     * exception type of the GCM encrypt guard, and a refusal does not stop the original data
     * from getting its tag again.
     */
    public void testDifferentDataAfterDoFinal()
        throws Exception
    {
        final byte[] longer = Arrays.append(AD, (byte)0);
        final byte[] shorter = Arrays.copyOf(AD, AD.length - 1);

        List<String> outcome = runSequence("doFinal, then different data", new Sequence()
        {
            public void run(GMacOps m, List<String> out)
            {
                m.init(KEY, IV);
                step(out, m, AD);
                step(out, m, AD2);
                step(out, m, longer);
                step(out, m, shorter);
                step(out, m, new byte[0]);
                m.reset();
                step(out, m, AD2);
                step(out, m, AD);
            }
        });

        String refused = IllegalStateException.class.getSimpleName();
        List<String> expected = new ArrayList<String>();
        expected.add(tag(TAG));
        for (int i = 0; i != 5; i++)
        {
            expected.add(refused);
        }
        expected.add(tag(TAG));
        assertEquals(expected, outcome);
    }

    /**
     * Re-initialising with the key and IV just used is refused by the GCM encrypt guard, and the
     * MAC then refuses everything, same data or not, until a successful init.
     */
    public void testReinitSameKeyAndIV()
        throws Exception
    {
        final byte[][] data = {AD, AD2};
        for (int d = 0; d != data.length; d++)
        {
            final byte[] next = data[d];
            List<String> outcome = runSequence("doFinal, re-init same key and IV, " + (d == 0 ? "same" : "different") + " data",
                new Sequence()
                {
                    public void run(GMacOps m, List<String> out)
                    {
                        m.init(KEY, IV);
                        step(out, m, AD);
                        stepInit(out, m, KEY, IV);
                        step(out, m, next);
                        m.reset();
                        step(out, m, next);
                        stepInit(out, m, KEY, IV2);
                        step(out, m, AD2);
                    }
                });

            List<String> expected = tags(TAG);
            expected.add(IllegalArgumentException.class.getSimpleName());
            expected.add(IllegalStateException.class.getSimpleName());
            expected.add(IllegalStateException.class.getSimpleName());
            expected.add("init");
            expected.add(tag(reference(IV2, AD2)));
            assertEquals(expected, outcome);
        }
    }

    /**
     * The refusal of different data says why, on every engine.
     */
    public void testDifferentDataMessage()
        throws Exception
    {
        GCMModeCipher[] engines = {new GCMBlockCipher(new AESEngine()), GCMBlockCipher.newInstance(AESEngine.newInstance())};
        for (int i = 0; i != engines.length; i++)
        {
            GMac mac = new GMac(engines[i]);
            mac.init(new ParametersWithIV(new KeyParameter(KEY), IV));
            byte[] out = new byte[16];
            mac.update(AD, 0, AD.length);
            mac.doFinal(out, 0);
            mac.update(AD2, 0, AD2.length);
            try
            {
                mac.doFinal(out, 0);
                fail("different data accepted");
            }
            catch (IllegalStateException e)
            {
                assertEquals(engines[i].getClass().getSimpleName(),
                    "GMAC cannot be reused with the same nonce over different data", e.getMessage());
            }
            // the refusal leaves the first tag in the output untouched.
            assertTrue(Arrays.areEqual(TAG, out));
        }
    }

    private static byte[] reference(byte[] iv, byte[] data)
    {
        GMacOps ref = new LightweightOps("reference", new GCMBlockCipher(new AESEngine()));
        ref.init(KEY, iv);
        ref.update(data);
        return ref.doFinal();
    }

    /**
     * A new IV starts afresh: the tag is the one a new MAC gives for that IV and data.
     */
    public void testReinitNewIV()
        throws Exception
    {
        final byte[] expected = reference(IV2, AD2);

        List<String> outcome = runSequence("doFinal, re-init new IV", new Sequence()
        {
            public void run(GMacOps m, List<String> out)
            {
                m.init(KEY, IV);
                step(out, m, AD);
                stepInit(out, m, KEY, IV2);
                step(out, m, AD2);
                step(out, m, AD2);
                step(out, m, AD);
            }
        });

        List<String> want = tags(TAG);
        want.add("init");
        want.add(tag(expected));
        want.add(tag(expected));
        want.add(IllegalStateException.class.getSimpleName());
        assertEquals(want, outcome);
    }

    private static String tag(byte[] t)
    {
        return TAG_PREFIX + Hex.toHexString(t);
    }

    private static List<String> tags(byte[]... ts)
    {
        List<String> res = new ArrayList<String>();
        for (int i = 0; i != ts.length; i++)
        {
            res.add(tag(ts[i]));
        }
        return res;
    }

    private List<String> runSequence(String label, Sequence seq)
        throws Exception
    {
        GMacOps[] ops = allOps();
        List<String> javaOutcome = null;

        StringBuilder report = new StringBuilder();
        report.append("GMAC reuse [").append(System.getProperty("org.bouncycastle.native.cpu_variant", "default"))
            .append("] ").append(label).append(":\n");

        for (int i = 0; i != ops.length; i++)
        {
            List<String> out = new ArrayList<String>();
            seq.run(ops[i], out);
            report.append("    ").append(ops[i].name()).append(": ").append(out).append('\n');

            List<String> comparable = ops[i].normalise(out);
            if (javaOutcome == null)
            {
                javaOutcome = comparable;
            }
            else
            {
                assertEquals(label + ": " + ops[i].name() + " differs from java GCM\n" + report, javaOutcome, comparable);
            }
        }

        System.out.print(report);
        return javaOutcome;
    }

    private static void step(List<String> out, GMacOps m, byte[] data)
    {
        try
        {
            m.update(data);
            out.add(TAG_PREFIX + Hex.toHexString(m.doFinal()));
        }
        catch (Exception e)
        {
            out.add(e.getClass().getSimpleName() + "(" + e.getMessage() + ")");
        }
    }

    private static void stepByteByByte(List<String> out, GMacOps m, byte[] data)
    {
        try
        {
            for (int i = 0; i != data.length; i++)
            {
                m.update(new byte[]{data[i]});
            }
            out.add(TAG_PREFIX + Hex.toHexString(m.doFinal()));
        }
        catch (Exception e)
        {
            out.add(e.getClass().getSimpleName() + "(" + e.getMessage() + ")");
        }
    }

    private static void stepInit(List<String> out, GMacOps m, byte[] key, byte[] iv)
    {
        try
        {
            m.init(key, iv);
            out.add("init");
        }
        catch (Exception e)
        {
            out.add(e.getClass().getSimpleName() + "(" + e.getMessage() + ")");
        }
    }

    private static GMacOps[] allOps()
        throws Exception
    {
        GCMModeCipher defaultGCM = GCMBlockCipher.newInstance(AESEngine.newInstance());
        return new GMacOps[]{
            new LightweightOps("GMac/java GCM", new GCMBlockCipher(new AESEngine())),
            new LightweightOps("GMac/" + defaultGCM.getClass().getSimpleName(), defaultGCM),
            new JceOps()
        };
    }

    private interface Sequence
    {
        void run(GMacOps m, List<String> out);
    }

    private interface GMacOps
    {
        String name();

        void init(byte[] key, byte[] iv);

        void update(byte[] data);

        byte[] doFinal();

        void reset();

        /**
         * Outcomes reduced to the tag or the exception type, with JCE exception types mapped to
         * the lightweight ones they wrap.
         */
        List<String> normalise(List<String> outcome);
    }

    private static class LightweightOps
        implements GMacOps
    {
        private final String name;
        private final GMac mac;

        LightweightOps(String name, GCMModeCipher cipher)
        {
            this.name = name;
            this.mac = new GMac(cipher);
        }

        public String name()
        {
            return name;
        }

        public void init(byte[] key, byte[] iv)
        {
            mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        }

        public void update(byte[] data)
        {
            mac.update(data, 0, data.length);
        }

        public byte[] doFinal()
        {
            byte[] out = new byte[mac.getMacSize()];
            mac.doFinal(out, 0);
            return out;
        }

        public void reset()
        {
            mac.reset();
        }

        public List<String> normalise(List<String> outcome)
        {
            List<String> res = new ArrayList<String>();
            for (int i = 0; i != outcome.size(); i++)
            {
                String s = outcome.get(i);
                res.add(s.startsWith(TAG_PREFIX) || s.equals("init") ? s : s.substring(0, s.indexOf('(')));
            }
            return res;
        }
    }

    private static class JceOps
        implements GMacOps
    {
        private final javax.crypto.Mac mac;

        JceOps()
            throws Exception
        {
            this.mac = javax.crypto.Mac.getInstance("AESGMAC", BouncyCastleProvider.PROVIDER_NAME);
        }

        public String name()
        {
            return "JCE AESGMAC";
        }

        public void init(byte[] key, byte[] iv)
        {
            try
            {
                mac.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new JceInitException(e);
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.toString(), e);
            }
        }

        public void update(byte[] data)
        {
            mac.update(data);
        }

        public byte[] doFinal()
        {
            return mac.doFinal();
        }

        public void reset()
        {
            mac.reset();
        }

        public List<String> normalise(List<String> outcome)
        {
            List<String> res = new ArrayList<String>();
            for (int i = 0; i != outcome.size(); i++)
            {
                String s = outcome.get(i);
                if (s.startsWith(TAG_PREFIX) || s.equals("init"))
                {
                    res.add(s);
                }
                else if (s.startsWith(JceInitException.class.getSimpleName()))
                {
                    // BaseMac reports a GMac init failure as InvalidAlgorithmParameterException.
                    res.add(IllegalArgumentException.class.getSimpleName());
                }
                else
                {
                    res.add(s.substring(0, s.indexOf('(')));
                }
            }
            return res;
        }
    }

    private static class JceInitException
        extends RuntimeException
    {
        JceInitException(InvalidAlgorithmParameterException e)
        {
            super("InvalidAlgorithmParameterException: " + e.getMessage(), e);
        }
    }
}
