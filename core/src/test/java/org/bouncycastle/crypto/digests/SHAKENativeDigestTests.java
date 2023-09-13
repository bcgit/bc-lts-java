package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.security.SecureRandom;

public class SHAKENativeDigestTests
        extends TestCase
{
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    @After
    public void tearDown()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    @Test
    public void testReturnLen() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SHAKEDigest jdig = new SHAKEDigest();

        SHAKENativeDigest ndig = new SHAKENativeDigest();
        TestCase.assertEquals(jdig.getByteLength(), ndig.getByteLength());
        TestCase.assertEquals(jdig.getDigestSize(), ndig.getDigestSize());

        // digest result tested elsewhere
        byte[] z = new byte[jdig.getDigestSize() * 2];
        TestCase.assertEquals(jdig.doFinal(z, 0), ndig.doFinal(z, 0));

    }

    public void testNoUpdateAfterSqueeze() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SHAKENativeDigest nd = new SHAKENativeDigest(256) {
            @Override
            public int doFinal(byte[] output, int outOff)
            {
                return doFinal(nativeRef.getReference(),output,outOff,output.length);
            }
        };
        nd.update((byte) 1);
        byte[] o = new byte[512];
        nd.doFinal(o, 0);
        try
        {
            nd.update(new byte[2], 0, 2);
            fail("update multi byte after doFinal");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("attempt to absorb while squeezing"));
        }

        try
        {
            nd.update((byte) 0);
            fail("update single byte after doFinal");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("attempt to absorb while squeezing"));
        }


    }


    @Test
    public void testSHAKEEmpty()
            throws Exception
    {

        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        Xof dig = SHAKEDigest.newInstance();
        byte[] res = new byte[dig.getDigestSize()];
        TestCase.assertEquals(32, dig.doFinal(res, 0));

        TestCase.assertTrue("Empty Digest result",
                Arrays.areEqual(res, Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")));

    }

//    @Test
//    public void testSHAKEFullStateEncoding()
//            throws Exception
//    {
//        if (!TestUtil.hasNativeService("SHAKE"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
//            {
//                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
//
//
//        byte[] msg = new byte[256];
//        SecureRandom rand = new SecureRandom();
//        rand.nextBytes(msg);
//
//
//        for (int t = 0; t < 256; t++)
//        {
//
//            SavableDigest dig = SHAKEDigest.newInstance();
//            dig.update(msg, 0, t);
//            byte[] state = dig.getEncodedState();
//
//            byte[] resAfterStateExtraction = new byte[dig.getDigestSize()];
//            TestCase.assertEquals(32, dig.doFinal(resAfterStateExtraction, 0));
//
//            SavableDigest dig2 = SHAKEDigest.newInstance(state, CryptoServicePurpose.AGREEMENT);
//            byte[] resStateRecreated = new byte[dig2.getDigestSize()];
//            TestCase.assertEquals(32, dig2.doFinal(resStateRecreated, 0));
//
//
//            SHAKEDigest javaDigest = new SHAKEDigest();
//            javaDigest.update(msg, 0, t);
//
//            byte[] resJava = new byte[javaDigest.getDigestSize()];
//            TestCase.assertEquals(32, javaDigest.doFinal(resJava, 0));
//
//
//            TestCase.assertTrue("native post state extraction", Arrays.areEqual(resJava, resAfterStateExtraction));
//            TestCase.assertTrue("native recreated from extracted state", Arrays.areEqual(resJava, resStateRecreated));
//        }
//    }


    public void testSHAKEByteByByte()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);

        Digest dig = SHAKEDigest.newInstance();
        SHAKEDigest javaDigest = new SHAKEDigest();

        for (int t = 0; t < 256; t++)
        {
            dig.update(msg[t]);
            javaDigest.update(msg[t]);
        }

        byte[] resJava = new byte[javaDigest.getDigestSize()];
        TestCase.assertEquals(32, javaDigest.doFinal(resJava, 0));

        byte[] nativeDigest = new byte[dig.getDigestSize()];
        TestCase.assertEquals(32, dig.doFinal(nativeDigest, 0));

        TestCase.assertTrue(" native byte by byte", Arrays.areEqual(resJava, nativeDigest));

    }


    /**
     * Prove that a digest created from the state of another one will calculate the same result with the same bytes as
     * input. Final value compared to java version.
     *
     * @throws Exception
     */
    @Test
    public void testSHAKEFullStateEncodingExtraData()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        boolean expectNative = CryptoServicesRegistrar.hasEnabledService(NativeServices.SHAKE);



        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);

        Arrays.fill(msg, (byte) 1);


        SavableDigestXof dig = SHAKEDigest.newInstance();

        if (expectNative) {
            TestCase.assertTrue(dig instanceof SHAKENativeDigest);
        } else {
            TestCase.assertTrue(dig instanceof SHAKEDigest);
        }


        dig.update(msg, 0, 12);
        byte[] state = dig.getEncodedState();


        SavableDigestXof dig2 = SHAKEDigest.newInstance(state, CryptoServicePurpose.AGREEMENT);

        if (expectNative) {
            TestCase.assertTrue(dig2 instanceof SHAKENativeDigest);
        } else {
            TestCase.assertTrue(dig2 instanceof SHAKEDigest);
        }

        dig.update(msg, 12, msg.length - 12);
        dig2.update(msg, 12, msg.length - 12);

        SHAKEDigest javaDigest = new SHAKEDigest();
        javaDigest.update(msg, 0, msg.length);

        byte[] d1Result = new byte[dig.getDigestSize()];
        byte[] d2Result = new byte[dig2.getDigestSize()];
        byte[] javaResult = new byte[javaDigest.getDigestSize()];

        TestCase.assertEquals(32, dig.doFinal(d1Result, 0));
        TestCase.assertEquals(32, dig2.doFinal(d2Result, 0));
        TestCase.assertEquals(32, javaDigest.doFinal(javaResult, 0));


        TestCase.assertTrue(Arrays.areEqual(javaResult, d1Result) && Arrays.areEqual(javaResult, d2Result));

    }

    public void testUpdateLimitEnforcement()
            throws Exception
    {


        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        new SHAKENativeDigest()
        {
            {
                try
                {
                    update(null, 0, 0);
                    fail("accepted null byte array");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("input was null"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    update(new byte[0], -1, 0);
                    fail("accepted negative input offset");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("offset is negative"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    update(new byte[0], 0, -1);
                    fail("accepted negative input len");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("len is negative"));
                }
            }
        };

        new SHAKENativeDigest()
        {
            {
                try
                {
                    update(new byte[1], 1, 1);
                    fail("accepted input past end of buffer");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {

                //
                // Pass in an array but with offset at the limit and zero length
                // Assert this works
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 19, 0);
                TestCase.assertEquals(32, doFinal(res, 0));

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                        ));
            }
        };


        new SHAKENativeDigest()
        {
            {

                //
                // Pass in an array but with offset at zero with zero length
                // Assert this doesn't process anything.
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 0, 0);
                TestCase.assertEquals(32, doFinal(res, 0));

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                        ));
            }
        };


    }

    public void testDoFinalLimitEnforcement()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(null, 0);
                    fail("accepted null byte array");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("output was null"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[0], -1);
                    fail("accepted negative output offset");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("offset is negative"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[0], 1);
                    fail("accept offset pas end of buffer");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("offset past end of array"));
                }
            }
        };

        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[20], 0);
                    fail("accepted output array too small");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("array + offset too short for digest output"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[20], 0,-1);
                    fail("accepted negative output len");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("output len is negative"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[20], 0,21);
                    fail("accepted specified len is past end of array .. 0 offset");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("array + offset too short for digest output"));
                }
            }
        };


        new SHAKENativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[20], 1,20);
                    fail("accepted specified len is past end of array .. offset");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("array + offset too short for digest output"));
                }
            }
        };

        new SHAKENativeDigest()
        {
            {
                //
                // Should result in result array with leading zero byte
                // followed by no-input digest value.
                //

                byte[] res = new byte[getDigestSize() + 1];
                TestCase.assertEquals(32, doFinal(res, 1));
                TestCase.assertTrue(
                        Arrays.areEqual(
                                Hex.decode("007f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
                                res)
                );

            }
        };

    }

    public void testRecreatingFromEncodedState()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHAKENativeDigest dig = new SHAKENativeDigest()
        {
            {
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 5);
            }
        };
        saneState = dig.getEncodedState();


        try
        {
            new SHAKENativeDigest().restoreState(null, 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("input was null"));
        }


        try
        {
            new SHAKENativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("array at offset too short for encoded input"));
        }


        try
        {
            new SHAKENativeDigest().restoreState(new byte[saneState.length], 0);
            fail("bad id");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }


        // At length should fail.
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);


            //
            // Our sane state has four bytes written to it, so both bufPtr and byteCount should be four.
            // Here we find every four in the state and set it to 64, because we cannot guarantee the position
            // within in the struct that the LSB of bufPtr will be.
            // This will enable us to assert that length checking of encoded bufPtr is correct.

            state[24] = (byte) 192;

            new SHAKENativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value at 192");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }


        // Over length should fail
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);


            state[24] = (byte) 193;

            new SHAKENativeDigest().restoreFullState(state, 0);
            fail("should fail on bufPtr value exceeding 193");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }

    }

    public void testRecreatingFromMemoable()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHAKENativeDigest dig = new SHAKENativeDigest()
        {
            {
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
            }
        };
        saneState = dig.getEncodedState();

        try
        {
            new SHAKENativeDigest().restoreState(null, 0);
            fail("accepted null");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("input was null"));
        }


        try
        {
            new SHAKENativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("array at offset too short for encoded input"));
        }


        try
        {
            // All zeroes.
            new SHAKENativeDigest().restoreFullState(new byte[saneState.length], 0);
            fail("bad id");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }


        // At length should fail.
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);


            //
            // Our sane state has four bytes written to it, so both bufPtr and byteCount should be four.
            // Here we find every four in the state and set it to 64, because we cannot guarantee the position
            // within in the struct that the LSB of bufPtr will be.
            // This will enable us to assert that length checking of encoded bufPtr is correct.

            state[24] = (byte) 193;

            new SHAKENativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 193");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }


        // Over length should fail
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);
            state[24] = (byte) 192;

            new SHAKENativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 192");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid shake encoded state"));
        }


    }

    @Test
    public void testMemoable()
            throws Exception
    {
        if (!TestUtil.hasNativeService("SHAKE"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                fail("Skipping SHAKE Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        // There are other tests for memoable, this is more of a sanity test

        SHAKENativeDigest dig1 = new SHAKENativeDigest();
        dig1.update((byte) 1);

        SHAKENativeDigest dig2 = new SHAKENativeDigest(dig1);

        SHAKEDigest jig1 = new SHAKEDigest();
        jig1.update((byte) 1);

        byte[] r1 = new byte[dig1.getDigestSize()];
        byte[] r2 = new byte[dig2.getDigestSize()];
        byte[] j1 = new byte[jig1.getDigestSize()];

        TestCase.assertEquals(32, dig1.doFinal(r1, 0));
        TestCase.assertEquals(32, dig2.doFinal(r2, 0));
        TestCase.assertEquals(32, jig1.doFinal(j1, 0));

        TestCase.assertTrue(Arrays.areEqual(j1, r1));
        TestCase.assertTrue(Arrays.areEqual(j1, r2));

    }



}