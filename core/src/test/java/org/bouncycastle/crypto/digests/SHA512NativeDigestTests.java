package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class SHA512NativeDigestTests
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
        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SHA512Digest jdig = new SHA512Digest();

        SHA512NativeDigest ndig = new SHA512NativeDigest();
        TestCase.assertEquals(jdig.getByteLength(), ndig.getByteLength());
        TestCase.assertEquals(jdig.getDigestSize(), ndig.getDigestSize());

        // digest result tested elsewhere
        byte[] z = new byte[jdig.getDigestSize() * 2];
        TestCase.assertEquals(jdig.doFinal(z, 0), ndig.doFinal(z, 0));

    }


    @Test
    public void testSHA512Empty()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SavableDigest dig = SHA512Digest.newInstance();
        byte[] res = new byte[dig.getDigestSize()];
        TestCase.assertEquals(64, dig.doFinal(res, 0));

        TestCase.assertTrue("Empty Digest result",
                Arrays.areEqual(res, Hex.decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")));

    }

    @Test
    public void testSHA512FullStateEncoding()
            throws Exception
    {
        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);


        for (int t = 0; t < 256; t++)
        {

            SavableDigest dig = SHA512Digest.newInstance();
            dig.update(msg, 0, t);
            byte[] state = dig.getEncodedState();

            byte[] resAfterStateExtraction = new byte[dig.getDigestSize()];
            TestCase.assertEquals(64, dig.doFinal(resAfterStateExtraction, 0));

            SavableDigest dig2 = SHA512Digest.newInstance(state, 0);
            byte[] resStateRecreated = new byte[dig2.getDigestSize()];
            TestCase.assertEquals(64, dig2.doFinal(resStateRecreated, 0));


            SHA512Digest javaDigest = new SHA512Digest();
            javaDigest.update(msg, 0, t);

            byte[] resJava = new byte[javaDigest.getDigestSize()];
            TestCase.assertEquals(64, javaDigest.doFinal(resJava, 0));


            TestCase.assertTrue("Java = native post state extraction", Arrays.areEqual(resJava, resAfterStateExtraction));
            TestCase.assertTrue("Java = native recreated from extracted state", Arrays.areEqual(resJava, resStateRecreated));
        }
    }


    public void testSHA512ByteByByte()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);

        SavableDigest dig = SHA512Digest.newInstance();
        SHA512Digest javaDigest = new SHA512Digest();

        for (int t = 0; t < 256; t++)
        {
            dig.update(msg[t]);
            javaDigest.update(msg[t]);
        }

        byte[] resJava = new byte[javaDigest.getDigestSize()];
        TestCase.assertEquals(64, javaDigest.doFinal(resJava, 0));

        byte[] nativeDigest = new byte[dig.getDigestSize()];
        TestCase.assertEquals(64, dig.doFinal(nativeDigest, 0));

        TestCase.assertTrue("Java = native byte by byte", Arrays.areEqual(resJava, nativeDigest));

    }


    /**
     * Prove that a digest created from the state of another one will calculate the same result with the same bytes as
     * input. Final value compared to java version.
     *
     * @throws Exception
     */
    @Test
    public void testSHA512FullStateEncodingExtraData()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);


        SavableDigest dig = SHA512Digest.newInstance();
        dig.update(msg, 0, 12);
        byte[] state = dig.getEncodedState();


        SavableDigest dig2 = SHA512Digest.newInstance(state, 0);

        dig.update(msg, 12, msg.length - 12);
        dig2.update(msg, 12, msg.length - 12);

        SHA512Digest javaDigest = new SHA512Digest();
        javaDigest.update(msg, 0, msg.length);

        byte[] d1Result = new byte[dig.getDigestSize()];
        byte[] d2Result = new byte[dig2.getDigestSize()];
        byte[] javaResult = new byte[javaDigest.getDigestSize()];

        TestCase.assertEquals(64, dig.doFinal(d1Result, 0));
        TestCase.assertEquals(64, dig2.doFinal(d2Result, 0));
        TestCase.assertEquals(64, javaDigest.doFinal(javaResult, 0));


        TestCase.assertTrue(Arrays.areEqual(javaResult, d1Result) && Arrays.areEqual(javaResult, d2Result));

    }

    public void testUpdateLimitEnforcement()
            throws Exception
    {


        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
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

        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
        {
            {

                //
                // Pass in an array but with offset at the limit and zero length
                // Assert this works
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 19, 0);
                TestCase.assertEquals(64, doFinal(res, 0));

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
                        ));
            }
        };


        new SHA512NativeDigest()
        {
            {

                //
                // Pass in an array but with offset at zero with zero length
                // Assert this doesn't process anything.
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 0, 0);
                TestCase.assertEquals(64, doFinal(res, 0));

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
                        ));
            }
        };


    }

    public void testDoFinalLimitEnforcement()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
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

        new SHA512NativeDigest()
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


        new SHA512NativeDigest()
        {
            {
                //
                // Should result in result array with leading zero byte
                // followed by no-input digest value.
                //

                byte[] res = new byte[getDigestSize() + 1];
                TestCase.assertEquals(64, doFinal(res, 1));
                TestCase.assertTrue(
                        Arrays.areEqual(
                                Hex.decode("00cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
                                res)
                );

            }
        };

    }

    public void testRecreatingFromEncodedState()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHA512NativeDigest dig = new SHA512NativeDigest()
        {
            {
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
            }
        };
        saneState = dig.getEncodedState();


        try
        {
            new SHA512NativeDigest().restoreState(null, 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("input was null"));
        }


        try
        {
            new SHA512NativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("array at offset too short for encoded input"));
        }


        try
        {
            new SHA512NativeDigest().restoreState(new byte[saneState.length], 0);
            fail("bad id");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
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

            for (int t = 0; t < state.length; t++)
            {
                if (state[t] == 4)
                {
                    state[t] = (byte) 128;
                    break;
                }
            }

            new SHA512NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
        }


        // Over length should fail
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);


            for (int t = 0; t < state.length; t++)
            {
                if (state[t] == 4)
                {
                    state[t] = (byte) 129;
                }
            }

            new SHA512NativeDigest().restoreFullState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
        }

    }

    public void testRecreatingFromMemoable()
            throws Exception
    {

        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }


        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHA512NativeDigest dig = new SHA512NativeDigest()
        {
            {
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
                update((byte) 1);
            }
        };
        saneState = dig.getEncodedState();

        try
        {
            new SHA512NativeDigest().restoreState(null, 0);
            fail("accepted null");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("input was null"));
        }


        try
        {
            new SHA512NativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("array at offset too short for encoded input"));
        }


        try
        {
            // All zeroes.
            new SHA512NativeDigest().restoreFullState(new byte[saneState.length], 0);
            fail("bad id");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
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

            for (int t = 0; t < state.length; t++)
            {
                if (state[t] == 4)
                {
                    state[t] = (byte) 128;
                }
            }

            new SHA512NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
        }


        // Over length should fail
        try
        {
            // Check bufPtr limit test

            byte[] state = Arrays.clone(saneState);


            for (int t = 0; t < state.length; t++)
            {
                if (state[t] == 4)
                {
                    state[t] = (byte) 129;
                }
            }

            new SHA512NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("invalid sha512 encoded state"));
        }


    }

    @Test
    public void testMemoable()
            throws Exception
    {
        if (!TestUtil.hasNativeService("SHA512"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha512"))
            {
                fail("Skipping SHA512 Limit Test: " + TestUtil.errorMsg());
            }
            return;
        }

        // There are other tests for memoable, this is more of a sanity test

        SHA512NativeDigest dig1 = new SHA512NativeDigest();
        dig1.update((byte) 1);

        SHA512NativeDigest dig2 = new SHA512NativeDigest(dig1);

        SHA512Digest jig1 = new SHA512Digest();
        jig1.update((byte) 1);

        byte[] r1 = new byte[dig1.getDigestSize()];
        byte[] r2 = new byte[dig2.getDigestSize()];
        byte[] j1 = new byte[jig1.getDigestSize()];

        TestCase.assertEquals(64, dig1.doFinal(r1, 0));
        TestCase.assertEquals(64, dig2.doFinal(r2, 0));
        TestCase.assertEquals(64, jig1.doFinal(j1, 0));

        TestCase.assertTrue(Arrays.areEqual(j1, r1));
        TestCase.assertTrue(Arrays.areEqual(j1, r2));

    }


}