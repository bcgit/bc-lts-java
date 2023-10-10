package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCTRPacketCipher;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class AESCTRPacketCipherTest
        extends TestCase
{
    public AESCTRPacketCipherTest() {

    }


    @Test
    public void testMultipleMessages()
            throws Exception
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        AESCTRModePacketCipher ctrPC = AESPacketCipherEngine.createCTRPacketCipher();
        SecureRandom rand = new SecureRandom();

        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);


            for (int ivLen : new int[]{16, 15, 14, 13, 12, 11, 10, 9, 8})
            {

                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);

                ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);


                StreamCipher javaEnc = new SICBlockCipher(new AESEngine());
                javaEnc.init(true, params);

                SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
                javaDec.init(false, params);


                //
                // We cannot do all the possible messages so limit it to 1025
                //
                int maxMsg = 1025;
                if (ivLen == 15)
                {
                    maxMsg = 255;
                }

                for (int l = 0; l < maxMsg; l++)
                {

                    for (int jitter = 0; jitter < 2; jitter++)
                    {

                        byte[] msg = new byte[l + jitter];
                        byte[] nct = new byte[l + jitter];
                        byte[] npt = new byte[l + jitter];
                        byte[] jct = new byte[l + jitter];
                        byte[] jpt = new byte[l + jitter];

                        rand.nextBytes(msg);

                        ctrPC.processPacket(true, params, msg, jitter, msg.length - jitter, nct, jitter);

                        javaEnc.processBytes(msg, jitter, msg.length - jitter, jct, jitter);

                        if (!Arrays.areEqual(jct, nct))
                        {
                            System.out.println(Hex.toHexString(jct));
                            System.out.println(Hex.toHexString(nct));
                        }

                        TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));
                        ctrPC.processPacket(true, params, nct, jitter, nct.length - jitter, npt, jitter);
                        javaDec.processBytes(jct, jitter, jct.length - jitter, jpt, jitter);


                        TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                        // The message array is filled with random data.
                        // Adding jitter shifts the process window by one byte.
                        // This means the plain text when jitter >0 will have leading zeros whereas the "msg"
                        // array will have random data, create a test data array that reflects this.

                        byte[] tstValue = Arrays.clone(msg);
                        for (int i = 0; i < jitter; i++)
                        {
                           tstValue[i] = 0;
                        }

                        TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(tstValue, npt));

                        javaDec.reset();
                        javaEnc.reset();
                    }
                }
            }
        }
    }


    @Test
    public void testMultipleMessagesBlocks()
            throws Exception
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom rand = new SecureRandom();
        AESCTRModePacketCipher ctrPC = AESPacketCipherEngine.createCTRPacketCipher();
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);


            for (int ivLen : new int[]{16, 15, 14, 13, 12, 11, 10, 9, 8})
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);

                ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

                SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
                javaEnc.init(true, params);

                SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
                javaDec.init(false, params);


                //
                // We cannot do all the possible messages so limit it to 1025
                //
                int maxMsg = 1025;
                if (ivLen == 15)
                {
                    maxMsg = 255;
                }

                for (int l = 0; l < maxMsg; l += 16)
                {

                    for (int jitter =0; jitter<2; jitter++)
                    {

                        byte[] msg = new byte[l+jitter];
                        byte[] nct = new byte[l+jitter];
                        byte[] npt = new byte[l+jitter];
                        byte[] jct = new byte[l+jitter];
                        byte[] jpt = new byte[l+jitter];

                        rand.nextBytes(msg);

                        ctrPC.processPacket(true, params, msg, jitter, msg.length-jitter, nct, jitter);
                        javaEnc.processBlocks(msg, jitter, (msg.length-jitter) / 16, jct, jitter);

                        if (!Arrays.areEqual(jct, nct))
                        {
                            System.out.println(Hex.toHexString(jct));
                            System.out.println(Hex.toHexString(nct));
                        }

                        TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                        ctrPC.processPacket(false, params, nct, jitter, nct.length-jitter, npt, jitter);
                        javaDec.processBlocks(jct, jitter, (jct.length-jitter) / 16, jpt, jitter);

                        TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                        byte[] tstMsg = Arrays.clone(msg);

                        for (int i =0; i <jitter; i++) {
                            tstMsg[i] = 0;
                        }

                        TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(tstMsg, npt));

                        javaDec.reset();
                        javaEnc.reset();
                    }
                }
            }
        }
    }


    @Test
    public void testExceptions()
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        AESCTRModePacketCipher ctr = AESPacketCipherEngine.createCTRPacketCipher();
        try
        {
            ctr.getOutputSize(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertEquals("wrong message", ExceptionMessage.LEN_NEGATIVE, e.getMessage());
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16],
                    0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
        }


        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0,
                    new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }


        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }




    /**
     * Tests operation of packet cipher where input and output arrays are the same
     *
     * @throws Exception
     */
    @Test
    public void testIntoSameArray() throws Exception
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        // Java implementation of CTR mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CTRModeCipher ctrModeCipherEnc = new SICBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        PacketCipher ctrPS = AESCTRPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(ctrPS.toString().contains("CTR-PS[Native]"));
            TestCase.assertTrue(ctrPS instanceof AESNativeCTRPacketCipher);
        }
        else
        {
            TestCase.assertTrue(ctrPS.toString().contains("CTR-PS[Java]"));
            TestCase.assertTrue(ctrPS instanceof AESCTRPacketCipher);
        }

        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
            ctrModeCipherEnc.init(true, cp);

            for (int t = 0; t < 2048; t += 16)
            {
                byte[] msg = new byte[t];
                secureRandom.nextBytes(msg);

                // We will slide around in the array also at odd addresses
                byte[] workingArray = new byte[2 + msg.length * 2];


                // Generate the expected cipher text from java CTR mode
                byte[] expectedCText = new byte[msg.length];
                ctrModeCipherEnc.reset();
                ctrModeCipherEnc.processBlocks(msg, 0, msg.length / 16, expectedCText, 0);


                for (int jitter : new int[]{0, 1})
                {
                    // Encryption
                    System.arraycopy(msg, 0, workingArray, jitter, msg.length);
                    int len = ctrPS.processPacket(true, cp, workingArray, jitter, msg.length, workingArray,
                            msg.length + jitter);
                    TestCase.assertEquals(msg.length, len);

                    // Check cipher text
                    for (int j = 0; j < msg.length; j++)
                    {
                        if (expectedCText[j] != workingArray[j + msg.length + jitter])
                        {
                            System.out.println(Hex.toHexString(workingArray));
                            System.out.println(Hex.toHexString(expectedCText));
                            System.out.println(jitter);
                            fail("cipher text not same");
                        }
                    }


                    // Destroy plain text section
                    // as it should be written over with the correct plain text
                    Arrays.fill(workingArray, jitter, msg.length + jitter, (byte) 1);


                    // Decryption
                    len = ctrPS.processPacket(false, cp, workingArray, msg.length + jitter, msg.length, workingArray,
                            jitter);
                    TestCase.assertEquals(msg.length, len);

                    // Check cipher text
                    for (int j = 0; j < msg.length; j++)
                    {
                        if (msg[j] != workingArray[j + jitter])
                        {
                            System.out.println(Hex.toHexString(workingArray));
                            System.out.println(Hex.toHexString(msg));
                            System.out.println(jitter);

                            fail("plain text not same");
                        }

                    }

                }

            }
        }
    }

    private boolean isNativeVariant()
    {
        String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
        if (variant == null || "java".equals(variant))
        {
            return false;
        }
        // May not be ported to native platform, so exercise java version only.
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CTR_PC);
    }

}
