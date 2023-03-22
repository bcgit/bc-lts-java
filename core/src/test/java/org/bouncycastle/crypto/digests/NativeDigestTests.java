package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class NativeDigestTests extends TestCase
{

    @Test
    public void testSHA256Empty() throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        SHA256NativeDigest dig = new SHA256NativeDigest();
        byte[] res = new byte[dig.getDigestSize()];
        dig.doFinal(res, 0);
        TestCase.assertTrue("Empty Digest result",
                Arrays.areEqual(res, Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));

    }

    @Test
    public void testSHA256FullStateEncoding() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);


        for (int t = 0; t < 256; t++)
        {

            SHA256NativeDigest dig = new SHA256NativeDigest();
            dig.update(msg, 0, t);
            byte[] state = dig.getEncodedState();

            byte[] resAfterStateExtraction = new byte[dig.getDigestSize()];
            dig.doFinal(resAfterStateExtraction, 0);

            SHA256NativeDigest dig2 = new SHA256NativeDigest().restoreState(state, 0);
            byte[] resStateRecreated = new byte[dig2.getDigestSize()];
            dig2.doFinal(resStateRecreated, 0);


            SHA256Digest javaDigest = new SHA256Digest();
            javaDigest.update(msg, 0, t);

            byte[] resJava = new byte[javaDigest.getDigestSize()];
            javaDigest.doFinal(resJava, 0);


            TestCase.assertTrue("Java = native post state extraction", Arrays.areEqual(resJava, resAfterStateExtraction));
            TestCase.assertTrue("Java = native recreated from extracted state", Arrays.areEqual(resJava, resStateRecreated));
        }
    }


    public void testSHA256ByteByByte() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);

        SHA256NativeDigest dig = new SHA256NativeDigest();
        SHA256Digest javaDigest = new SHA256Digest();

        for (int t = 0; t < 256; t++)
        {
            dig.update(msg[t]);
            javaDigest.update(msg[t]);
        }

        byte[] resJava = new byte[javaDigest.getDigestSize()];
        javaDigest.doFinal(resJava, 0);

        byte[] nativeDigest = new byte[dig.getDigestSize()];
        dig.doFinal(nativeDigest, 0);

        TestCase.assertTrue("Java = native byte by byte", Arrays.areEqual(resJava, nativeDigest));

    }


    /**
     * Prove that a digest created from the state of another one will calculate the same result with the same bytes as
     * input. Final value compared to java version.
     *
     * @throws Exception
     */
    @Test
    public void testSHA256FullStateEncodingExtraData() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        byte[] msg = new byte[256];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(msg);


        SHA256NativeDigest dig = new SHA256NativeDigest();
        dig.update(msg, 0, 12);
        byte[] state = dig.getEncodedState();


        SHA256NativeDigest dig2 = new SHA256NativeDigest().restoreState(state, 0);

        dig.update(msg, 12, msg.length - 12);
        dig2.update(msg, 12, msg.length - 12);

        SavableDigest javaDigest = new SHA256Digest();
        javaDigest.update(msg, 0, msg.length);

        byte[] d1Result = new byte[dig.getDigestSize()];
        byte[] d2Result = new byte[dig2.getDigestSize()];
        byte[] javaResult = new byte[javaDigest.getDigestSize()];

        dig.doFinal(d1Result, 0);
        dig2.doFinal(d2Result, 0);
        javaDigest.doFinal(javaResult, 0);

        TestCase.assertTrue(Arrays.areEqual(javaResult, d1Result) && Arrays.areEqual(javaResult, d2Result));

    }


    public void testUpdateLimitEnforcement() throws Exception
    {


        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        new SHA256NativeDigest()
        {
            {
                try
                {
                    update(null, 0, 0);
                    fail("accepted null byte array");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("input is null"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {
                try
                {
                    update(new byte[0], -1, 0);
                    fail("accepted negative input offset");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("inOff is negative"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {
                try
                {
                    update(new byte[0], 0, -1);
                    fail("accepted negative input len");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("len is negative"));
                }
            }
        };

        new SHA256NativeDigest()
        {
            {
                try
                {
                    update(new byte[1], 1, 1);
                    fail("accepted input past end of buffer");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("exceeds input length"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {

                //
                // Pass in an array but with offset at the limit and zero length
                // Assert this works
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 19, 0);
                doFinal(res, 0);

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                        ));
            }
        };


        new SHA256NativeDigest()
        {
            {

                //
                // Pass in an array but with offset at zero with zero length
                // Assert this doesn't process anything.
                //

                byte[] res = new byte[getDigestSize()];
                update(new byte[20], 0, 0);
                doFinal(res, 0);

                TestCase.assertTrue("Empty Digest result",
                        Arrays.areEqual(
                                res,
                                Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                        ));
            }
        };


    }

    public void testDoFinalLimitEnforcement() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        new SHA256NativeDigest()
        {
            {
                try
                {
                    doFinal(null, 0);
                    fail("accepted null byte array");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("output is null"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[0], -1);
                    fail("accepted negative output offset");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("outOff is negative"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[0], 1);
                    fail("accept offset pas end of buffer");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("exceeds output length"));
                }
            }
        };

        new SHA256NativeDigest()
        {
            {
                try
                {
                    doFinal(new byte[20], 0);
                    fail("accepted output array too small");
                } catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("too small for digest result"));
                }
            }
        };


        new SHA256NativeDigest()
        {
            {
                //
                // Should result in result array with leading zero byte
                // followed by no-input digest value.
                //

                byte[] res = new byte[getDigestSize() + 1];
                doFinal(res, 1);
                TestCase.assertTrue(
                        Arrays.areEqual(
                                Hex.decode("00e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                                res)
                );

            }
        };

    }

    public void testRecreatingFromEncodedState() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHA256NativeDigest dig = new SHA256NativeDigest()
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
            new SHA256NativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("less than size of SHA256FullStateType"));
        }


        try
        {
            new SHA256NativeDigest().restoreState(new byte[saneState.length - 1], 0);
            fail("bad id");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("unrecognized id"));
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
                    state[t] = 64;
                }
            }

            new SHA256NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("exceeds buffer length"));
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
                    state[t] = 65;
                }
            }

            new SHA256NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("exceeds buffer length"));
        }

    }


    public void testRecreatingFromMemoable() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        //
        // Generate the sane state, we need to do this as runtime as it may very because of alignment.
        //
        final byte[] saneState;

        SHA256NativeDigest dig = new SHA256NativeDigest()
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
            new SHA256NativeDigest().restoreState(new byte[saneState.length - 2], 0);
            fail("too short");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("less than size of SHA256FullStateType"));
        }


        try
        {
            new SHA256NativeDigest().restoreState(new byte[saneState.length - 1], 0);
            fail("bad id");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("unrecognized id"));
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
                    state[t] = 64;
                }
            }

            new SHA256NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("exceeds buffer length"));
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
                    state[t] = 65;
                }
            }

            new SHA256NativeDigest().restoreState(state, 0);
            fail("should fail on bufPtr value exceeding 64");
        } catch (Exception ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("exceeds buffer length"));
        }

    }


    @Test
    public void testMemoable() throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                fail("no native sha and no skip set for it");
                return;
            }
            System.out.println("Skipping testSHA256Empty, no native sha256: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        // There are other tests for memoable, this is more of a sanity test

        SHA256NativeDigest dig1 = new SHA256NativeDigest();
        dig1.update((byte) 1);

        SHA256NativeDigest dig2 = new SHA256NativeDigest(dig1);

        SHA256Digest jig1 = new SHA256Digest();
        jig1.update((byte) 1);

        byte[] r1 = new byte[dig1.getDigestSize()];
        byte[] r2 = new byte[dig2.getDigestSize()];
        byte[] j1 = new byte[jig1.getDigestSize()];

        dig1.doFinal(r1, 0);
        dig2.doFinal(r2, 0);
        jig1.doFinal(j1, 0);

        TestCase.assertTrue(Arrays.areEqual(j1, r1));
        TestCase.assertTrue(Arrays.areEqual(j1, r2));

    }

}
