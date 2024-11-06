package org.bouncycastle.pqc.crypto.slhdsa;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;


public class SlhDSASha256NativeLimitTest extends TestCase
{


    public void testInitMemoStatesPaddingPad1() throws Exception
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService(NativeServices.SLHDSA_SHA256))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("slhdsa_sha256"))
            {
                fail("no native slhdsa sha256 and test not set up to igore it");
                return;
            }
            System.out.println("Skipping SLHDSA SHA 256 native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        long ref = 0;
        try
        {
            ref = SLHDSASha2NativeEngine.makeInstance();


            //
            // Null seed
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, null, null, 0, 0);
                fail("Null seed");
            }
            catch (NullPointerException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("seed was null"));
            }


            //
            // Null padding
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], null, 0, 0);
                fail("Null padding");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("padding is null"));
            }

            // Offset hard coded 0 so no need to check offset is negative

            //
            // Padlen1 is negative
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[0], -1, 0);
                fail("Padlen1 is negative");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("pad1Len is negative"));
            }

            //
            // Padlen1 is past end of padding byte array
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[1], 2, 0);
                fail("Padlen1 is past end of padding byte array");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("padding too short"));
            }

            //
            // Padlen1 is within range
            //

            SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[1], 1, 0);


        }
        finally
        {
            SLHDSASha2NativeEngine.dispose(ref);
        }
    }

    public void testInitMemoStatesPaddingPad2() throws Exception
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService(NativeServices.SLHDSA_SHA256))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("slhdsa_sha256"))
            {
                fail("no native slhdsa sha256 and test not set up to igore it");
                return;
            }
            System.out.println("Skipping SLHDSA SHA 256 native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        long ref = 0;
        try
        {
            ref = SLHDSASha2NativeEngine.makeInstance();


            //
            // Null seed
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, null, null, 0, 0);
                fail("Null seed");
            }
            catch (NullPointerException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("seed was null"));
            }


            //
            // Null padding
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], null, 0, 0);
                fail("padding is null");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("padding is null"));
            }

            // Offset hard coded 0 so no need to check offset is negative

            //
            // Padlen1 is negative
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[0], 0, -1);
                fail("pad2Len is negative");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("pad2Len is negative"));
            }

            //
            // Padlen2 is past end of padding byte array
            //
            try
            {
                SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[1], 0, 2);
                fail("padding too short");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("padding too short"));
            }

            //
            // Padlen1 is within range
            //

            SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[1], 0, 1);

            //
            // Check both padding lengths are ok
            //
            SLHDSASha2NativeEngine.initMemoStates(ref, new byte[10], new byte[1], 1, 1);

        }
        finally
        {
            SLHDSASha2NativeEngine.dispose(ref);
        }
    }


    public void testSha256DigestAndReturnRange1() throws Exception
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService(NativeServices.SLHDSA_SHA256))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("slhdsa_sha256"))
            {
                fail("no native slhdsa sha256 and test not set up to igore it");
                return;
            }
            System.out.println("Skipping SLHDSA SHA 256 native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        long ref = 0;
        try
        {
            ref = SLHDSASha2NativeEngine.makeInstance();

            //
            // Accepts all null inputs
            //
            SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, null, null, null, null, null, null);

            //
            // Output less than digest len
            //
            try
            {
                SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, new byte[31], null, null, null, null, null);
                fail("Output less than digest len");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("output array too short"));
            }

            {
                //
                // Output array len == 32
                //
                byte[] output = new byte[32];
                SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, output, null, null, null, null, null);
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));

                //
                // Output array len == 33, expect trailing zero byte
                //
                output = new byte[33];
                SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, output, null, null, null, null, null);
                // note trailing zero
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"), output));
            }


            {
                //
                // Short range array
                //
                byte[] output = new byte[32];
                byte[] range = new byte[2];
                byte[] zulu = SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, output, range, null, null, null, null);
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0"), range));
                TestCase.assertTrue(Arrays.areEqual(range, zulu));


                //
                // Long range array
                //
                output = new byte[32];
                range = new byte[33];
                Arrays.fill(range, (byte) 0xFF);
                zulu = SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, output, range, null, null, null, null);

                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));
                // note trailing 0xFF
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855FF"), range));
                TestCase.assertTrue(Arrays.areEqual(range, zulu));

            }


            { // Assert each input applied
                byte[] output = new byte[32];
                byte[] expected = Hex.decode("26058196bd6ec9e05777b5d129a7485b3e9d3f723ce6027f40b8cd5efe26dc63"); // SHA256('aaabbbcccddd')

                SLHDSASha2NativeEngine.sha256DigestAndReturnRange(ref, false, output, null,
                        Strings.toByteArray("aaa"),
                        Strings.toByteArray("bbb"),
                        Strings.toByteArray("ccc"),
                        Strings.toByteArray("ddd"));
                TestCase.assertTrue(Arrays.areEqual(expected, output));
            }


        }
        finally
        {
            SLHDSASha2NativeEngine.dispose(ref);
        }
    }

    public void testMsgDigestAndReturnRange() throws Exception
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService(NativeServices.SLHDSA_SHA256))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("slhdsa_sha256"))
            {
                fail("no native slhdsa sha256 and test not set up to igore it");
                return;
            }
            System.out.println("Skipping SLHDSA SHA 256 native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        long ref = 0;
        try
        {
            ref = SLHDSASha2NativeEngine.makeInstance();

            //
            // Accepts all null inputs
            //
            SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, null, null, null, null, null, null, null);

            //
            // Output less than digest len
            //
            try
            {
                SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, new byte[31], null, null, null, null, null, null);
                fail("Output less than digest len");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("output array too short"));
            }

            {
                //
                // Output array len == 32
                //
                byte[] output = new byte[32];
                SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, output, null, null, null, null, null, null);
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));

                //
                // Output array len == 33, expect trailing zero byte
                //
                output = new byte[33];
                SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, output, null, null, null, null, null, null);
                // note trailing zero
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"), output));
            }


            {
                //
                // Short range array
                //
                byte[] output = new byte[32];
                byte[] range = new byte[2];
                byte[] zulu = SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, output, range, null, null, null, null, null);
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0"), range));
                TestCase.assertTrue(Arrays.areEqual(range, zulu));


                //
                // Long range array
                //
                output = new byte[32];
                range = new byte[33];
                Arrays.fill(range, (byte) 0xFF);
                zulu = SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, output, range, null, null, null, null, null);

                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), output));
                // note trailing 0xFF
                TestCase.assertTrue(Arrays.areEqual(Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855FF"), range));
                TestCase.assertTrue(Arrays.areEqual(range, zulu));

            }


            { // Assert each input applied
                byte[] output = new byte[32];
                byte[] expected = Hex.decode("5863234886ec5751a546be65c49a4cab88ff7ed12efb4676173e6df60bfe735f"); // SHA256('eeefffggghhhiii')

                SLHDSASha2NativeEngine.msgDigestAndReturnRange(ref, false, output, null,
                        Strings.toByteArray("eee"),
                        Strings.toByteArray("fff"),
                        Strings.toByteArray("ggg"),
                        Strings.toByteArray("hhh"),
                        Strings.toByteArray("iii")
                );

                TestCase.assertTrue(Arrays.areEqual(expected, output));

            }


        }
        finally
        {
            SLHDSASha2NativeEngine.dispose(ref);
        }
    }

    public void testBitmaskFunction() throws Exception
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService(NativeServices.SLHDSA_SHA256))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("slhdsa_sha256"))
            {
                fail("no native slhdsa sha256 and test not set up to igore it");
                return;
            }
            System.out.println("Skipping SLHDSA SHA 256 native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        long ref = 0;
        try
        {
            ref = SLHDSASha2NativeEngine.makeInstance();

            try // Key null
            {
                SLHDSASha2NativeEngine.bitmask(ref, null, new byte[32], new byte[0], null, null, null);
                fail("Key null");
            }
            catch (NullPointerException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("key is null"));
            }

            try // Key size
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[47], new byte[32], new byte[0], null, null, null);
                fail("Key size");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("key less than 48 bytes"));
            }


            // Valid key size
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[32], new byte[0], null, null, null);

            try // result  null
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[48], null, new byte[0], null, null, null);
                fail("result null");
            }
            catch (NullPointerException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("result is null"));
            }

            // Accepts the following as valid input
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[0], new byte[0], null, null, null);
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[2], new byte[1], null, null, null);
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], new byte[1], null, null, null);
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, new byte[1], null, null);
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, null, new byte[1], null);
            SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, null, null, new byte[1]);

            try
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], new byte[2], null, null, null);
                fail("result array too small 1");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("result array too small"));
            }

            try
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, new byte[2], null, null);
                fail("result array too small 2");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("result array too small"));
            }


            try
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, null, new byte[2], null);
                fail("result array too small 3");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("result array too small"));
            }

            try
            {
                SLHDSASha2NativeEngine.bitmask(ref, new byte[48], new byte[1], null, null, null, new byte[2]);
                fail("result array too small 4");
            }
            catch (IllegalArgumentException npe)
            {
                TestCase.assertTrue(npe.getMessage().contains("result array too small"));
            }

        }
        finally
        {
            SLHDSASha2NativeEngine.dispose(ref);
        }
    }

}
