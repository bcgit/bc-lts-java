package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class SHAKEJavaAgreementTest extends TestCase
{

    @Before
    public void before()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    @After
    public void after()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    private byte[] takeDigestXof(int bitLen, byte[] message, boolean expectNative, int len, int outputOffset, int inputOffset) throws Exception
    {

        Xof dig = SHAKEDigest.newInstance(bitLen);


        if (expectNative)
        {
            TestCase.assertTrue(dig.toString().contains("SHAKE[Native]"));
        }
        else
        {
            TestCase.assertTrue(dig.toString().contains("SHAKE[Java]"));
        }

        byte[] res = new byte[len + outputOffset];
        dig.update(message, inputOffset, message.length - inputOffset);
        if (len < 2)
        {
            dig.doOutput(res, outputOffset, len);
        }
        else
        {
            int l = dig.doOutput(res, outputOffset, len / 2);
            dig.doOutput(res, outputOffset + l, len - l);
        }

        return res;
    }

    private byte[] takeDigestFixedLen(int bitLen, byte[] message, boolean expectNative, int outputOffset, int inputOffset) throws Exception
    {

        Digest dig = SHAKEDigest.newInstance(bitLen);

        if (expectNative)
        {
            TestCase.assertTrue(dig.toString().contains("SHAKE[Native]"));
        }
        else
        {
            TestCase.assertTrue(dig.toString().contains("SHAKE[Java]"));
        }

        int len = dig.getDigestSize();

        byte[] res = new byte[len + outputOffset];
        dig.update(message, inputOffset, message.length - inputOffset);
        dig.doFinal(res, outputOffset);
        return res;
    }


    public void testAlgoName() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }

        for (int bitLen : new int[]{128, 256})
        {
            SHAKENativeDigest nd = new SHAKENativeDigest(bitLen);
            SHAKEDigest dig = new SHAKEDigest(bitLen);

            TestCase.assertEquals(nd.getAlgorithmName(), dig.getAlgorithmName());
        }
    }


    /**
     * Test variable length random input from zero to 1025 bytes.
     *
     * @throws Exception
     */
    @Test
    public void testXof() throws Exception
    {

        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom random = new SecureRandom();

        for (int bitLen : new int[]{128, 256})
        {
            for (int t = 0; t < 1025; t++)
            {
                byte[] msg = new byte[t];
                random.nextBytes(msg);
                for (int len = 0; len < 128; len++)
                {

                    // Introduce jitter to the output where the start of writing to the output
                    // array is potentially unaligned
                    for (int writeOffset = 0; writeOffset < 2; writeOffset++)
                    {

                        CryptoServicesRegistrar.setNativeEnabled(false);
                        byte[] java = takeDigestXof(bitLen, msg, false, len, writeOffset, 0);

                        CryptoServicesRegistrar.setNativeEnabled(true);
                        byte[] nativeDigest = takeDigestXof(bitLen, msg, true, len, writeOffset, 0);


                        boolean equal = Arrays.areEqual(java, nativeDigest);

                        if (!equal)
                        {
                            System.out.println(bitLen);
                            System.out.println(len);
                            System.out.println("MSG: " + Hex.toHexString(msg));
                            System.out.println("JAV: " + Hex.toHexString(java));
                            System.out.println("NAT: " + Hex.toHexString(nativeDigest));
                        }

                        TestCase.assertTrue(equal);

                        if (msg.length > 0)
                        {
                            //
                            // Exercise offset loading where the input is potentially unaligned.
                            //
                            CryptoServicesRegistrar.setNativeEnabled(false);
                            java = takeDigestXof(bitLen, msg, false, len, writeOffset, 1);

                            CryptoServicesRegistrar.setNativeEnabled(true);
                            nativeDigest = takeDigestXof(bitLen, msg, true, len, writeOffset, 1);

                            TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));
                        }


                    }
                }
            }
        }

    }


    public void testXofMonteCarlo_128() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom rand = new SecureRandom();
        byte[] msg = new byte[1023];
        rand.nextBytes(msg);

        SHAKEDigest javaDig = new SHAKEDigest(128);
        javaDig.update(msg, 1, msg.length-1);

        SHAKENativeDigest nativeDig = new SHAKENativeDigest(128);
        nativeDig.update(msg, 1, msg.length-1);

        int bl = 256;

        byte[] outputBufJava = new byte[bl];
        byte[] outputBufNative = new byte[bl];

        for (int t = 0; t < 1000000; t++)
        {
            //
            // Randomise offset, then fill to some random length
            //
            int offset = rand.nextInt(bl+1);
            int l = rand.nextInt(bl - offset+1);

            javaDig.doOutput(outputBufJava, offset, l);
            nativeDig.doOutput(outputBufNative, offset, l);


            if (!Arrays.areEqual(outputBufJava,outputBufNative)) {
                System.out.println(Hex.toHexString(outputBufJava));
                System.out.println(Hex.toHexString(outputBufNative));
                for (int i =0; i < outputBufJava.length;i++) {
                    if (outputBufJava[i] != outputBufNative[i]) {
                        System.out.print("^^");
                    } else {
                        System.out.print("  ");
                    }
                }
                System.out.println();
            }

            // This holds regardless of length
            TestCase.assertTrue(Arrays.areEqual(outputBufJava, outputBufNative));

        }

    }

    public void testXofMonteCarlo_256() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom rand = new SecureRandom();
        byte[] msg = new byte[1023];
        rand.nextBytes(msg);

        SHAKEDigest javaDig = new SHAKEDigest(256);
        javaDig.update(msg, 1, msg.length-1);

        SHAKENativeDigest nativeDig = new SHAKENativeDigest(256);
        nativeDig.update(msg, 1, msg.length-1);

        int bl = 256;

        byte[] outputBufJava = new byte[bl];
        byte[] outputBufNative = new byte[bl];

        for (int t = 0; t < 1000000; t++)
        {
            //
            // Randomise offset, then fill to some random length
            //
            int offset = rand.nextInt(bl+1);
            int l = rand.nextInt(bl - offset +1);

            javaDig.doOutput(outputBufJava, offset, l);
            nativeDig.doOutput(outputBufNative, offset, l);


            if (!Arrays.areEqual(outputBufJava,outputBufNative)) {
                System.out.println(Hex.toHexString(outputBufJava));
                System.out.println(Hex.toHexString(outputBufNative));
                for (int i =0; i < outputBufJava.length;i++) {
                    if (outputBufJava[i] != outputBufNative[i]) {
                        System.out.print("^^");
                    } else {
                        System.out.print("  ");
                    }
                }
                System.out.println();
            }

            // This holds regardless of length
            TestCase.assertTrue(Arrays.areEqual(outputBufJava, outputBufNative));

        }

    }

    /**
     * Test variable length random input from zero to 1025 bytes.
     *
     * @throws Exception
     */
    @Test
    public void testFixedLen() throws Exception
    {

        if (!TestUtil.hasNativeService(NativeServices.SHAKE))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("shake"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom random = new SecureRandom();

        for (int bitLen : new int[]{128, 256})
        {
            for (int t = 0; t < 1025; t++)
            {
                byte[] msg = new byte[t];
                random.nextBytes(msg);
                for (int len = 0; len < 128; len++)
                {

                    // Introduce jitter to the output where the start of writing to the output
                    // array is potentially unaligned
                    for (int writeOffset = 0; writeOffset < 2; writeOffset++)
                    {

                        CryptoServicesRegistrar.setNativeEnabled(false);
                        byte[] java = takeDigestFixedLen(bitLen, msg, false, writeOffset, 0);

                        CryptoServicesRegistrar.setNativeEnabled(true);
                        byte[] nativeDigest = takeDigestFixedLen(bitLen, msg, true, writeOffset, 0);

                        TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));

                        if (msg.length > 0)
                        {
                            //
                            // Exercise offset loading where the input is potentially unaligned.
                            //
                            CryptoServicesRegistrar.setNativeEnabled(false);
                            java = takeDigestFixedLen(bitLen, msg, false, writeOffset, 1);

                            CryptoServicesRegistrar.setNativeEnabled(true);
                            nativeDigest = takeDigestFixedLen(bitLen, msg, true, writeOffset, 1);

                            TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));
                        }


                    }
                }
            }
        }

    }


}
