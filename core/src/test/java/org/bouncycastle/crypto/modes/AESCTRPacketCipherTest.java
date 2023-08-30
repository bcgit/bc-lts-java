package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCTR;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

public class AESCTRPacketCipherTest
    extends TestCase
{
    public static void main(
        String[] args)
        throws Exception
    {
        AESCTRPacketCipherTest test = new AESCTRPacketCipherTest();
        test.performTest();
        System.out.println("AESCTRPacketCipherTest Pass");
    }

    @Test
    public void performTest()
        throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        Tests();
        CryptoServicesRegistrar.setNativeEnabled(false);
        Tests();
    }

    public void Tests()
        throws Exception
    {
        testExceptions();
        testSpreadArray();
        testSpreadProcessBlocks();
        testSpreadArrayWithOffsets();
    }


    @Before
    public void setUp()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    private void moveCtrToEnd(int ivLen, SkippingStreamCipher cipher)
        throws Exception
    {
        cipher.seekTo(0);

        if (ivLen == 8 || ivLen == 16)
        {

            for (int t = 0; t < 32; t++)
            {
                cipher.skip(Long.MAX_VALUE);
                cipher.skip(1);
            }

        }
        else if (ivLen > 8)
        {
            long maxBlock = 0;
            for (int j = 0; j < 16 - ivLen; j++)
            {
                maxBlock <<= 8;
                maxBlock |= 0xFF;
            }

            cipher.seekTo((maxBlock + 1) * 16);
        }
    }


    @Test
    public void testSeekingIntoFirstInvalidBlock()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CTR"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
//            {
//                TestCase.fail("Skipping CTR testSeekingIntoFirstInvalidBlock: " + TestUtil.errorMsg());
//            }
//            return;
//        }


        AESNativeCTR ctr = new AESNativeCTR();
        SecureRandom rand = new SecureRandom();


        int[] ivLens = new int[]{15, 14, 13, 12, 11, 10, 9, 8, 16};


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            for (int ivLen : ivLens)
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);

                ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

                AESNativeCTR nativeEnc = new AESNativeCTR();
                nativeEnc.init(true, params);

                moveCtrToEnd(ivLen, nativeEnc);
                nativeEnc.skip(0); // should work.

                for (int j = 1; j < 16; j++)
                {
                    try
                    {
                        nativeEnc.skip(j);
                        TestCase.fail("Expected exception");
                    }
                    catch (Exception ex)
                    {
                        TestCase.assertTrue(ex.getMessage().contains("out of range"));
                    }
                }

                nativeEnc.skip(-16);

                for (int j = 17; j < 32; j++)
                {
                    try
                    {
                        nativeEnc.skip(j);
                        TestCase.fail("Expected exception");
                    }
                    catch (Exception ex)
                    {
                        TestCase.assertTrue(ex.getMessage().contains("out of range"));
                    }
                }
            }
        }


    }


    @Test
    public void testSpreadArray()
        throws Exception
    {

//        if (!TestUtil.hasNativeService("AES/CTR"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
//            {
//                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
//            }
//            return;
//        }

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

//                AESNativeCTR nativeEnc = new AESNativeCTR();
//                nativeEnc.init(true, params);
//
//                AESNativeCTR nativeDec = new AESNativeCTR();
//                nativeDec.init(false, params);

                StreamCipher javaEnc = new SICBlockCipher(new AESEngine());
                javaEnc.init(true, params);

                SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
                javaDec.init(false, params);


                //
                // We cannot do all the possible messages so limit it to 65535
                //
                int maxMsg = 1024;
                if (ivLen == 15)
                {
                    maxMsg = 255;
                }

                for (int l = 2; l < maxMsg; l++)
                {


                    byte[] msg = new byte[l];
                    byte[] nct = new byte[l];
                    byte[] npt = new byte[l];
                    byte[] jct = new byte[l];
                    byte[] jpt = new byte[l];

                    rand.nextBytes(msg);

                    ctrPC.processPacket(true, params, msg, 0, msg.length, nct, 0);
                    //nativeEnc.processBytes(msg, 0, msg.length, nct, 0);


                    javaEnc.processBytes(msg, 0, msg.length, jct, 0);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));
                    ctrPC.processPacket(true, params, nct, 0, nct.length, npt, 0);
                    //nativeDec.processBytes(nct, 0, nct.length, npt, 0);
                    javaDec.processBytes(jct, 0, jct.length, jpt, 0);


                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

//                    nativeDec.reset();
//                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }


    @Test
    public void testSpreadProcessBlocks()
        throws Exception
    {

//        if (!TestUtil.hasNativeService("AES/CTR"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
//            {
//                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
//            }
//            return;
//        }


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

//                AESNativeCTR nativeEnc = new AESNativeCTR();
//                nativeEnc.init(true, params);
//
//                AESNativeCTR nativeDec = new AESNativeCTR();
//                nativeDec.init(false, params);

                SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
                javaEnc.init(true, params);

                SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
                javaDec.init(false, params);


                //
                // We cannot do all the possible messages so limit it to 65535
                //
                int maxMsg = 1024;
                if (ivLen == 15)
                {
                    maxMsg = 255;
                }

                for (int l = 0; l < maxMsg; l += 16)
                {
                    byte[] msg = new byte[l];
                    byte[] nct = new byte[l];
                    byte[] npt = new byte[l];
                    byte[] jct = new byte[l];
                    byte[] jpt = new byte[l];

                    rand.nextBytes(msg);

                    ctrPC.processPacket(true, params, msg, 0, msg.length, nct, 0);
                    javaEnc.processBlocks(msg, 0, msg.length / 16, jct, 0);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    ctrPC.processPacket(false, params, nct, 0, nct.length, npt, 0);
                    javaDec.processBlocks(jct, 0, jct.length / 16, jpt, 0);

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

//                    nativeDec.reset();
//                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }


    @Test
    public void testSpreadArrayWithOffsets()
        throws Exception
    {

//        if (!TestUtil.hasNativeService("AES/CTR"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
//            {
//                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
//            }
//            return;
//        }


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

//                AESNativeCTR nativeEnc = new AESNativeCTR();
//                nativeEnc.init(true, params);
//
//                AESNativeCTR nativeDec = new AESNativeCTR();
//                nativeDec.init(false, params);

                SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
                javaEnc.init(true, params);

                SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
                javaDec.init(false, params);


                //
                // We cannot do all the possible messages so limit it to 65535
                //
                int maxMsg = 1024;
                if (ivLen == 15)
                {
                    maxMsg = 255;
                }

                for (int l = 0; l < maxMsg; l++)
                {
                    byte[] msg = new byte[l];
                    byte[] nct = new byte[l + 1];
                    byte[] npt = new byte[l];
                    byte[] jct = new byte[l + 1];
                    byte[] jpt = new byte[l];

                    rand.nextBytes(msg);
                    ctrPC.processPacket(true, params, msg, 0, msg.length, nct, 1);
//                    nativeEnc.processBytes(msg, 0, msg.length, nct, 1);
                    javaEnc.processBytes(msg, 0, msg.length, jct, 1);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    ctrPC.processPacket(false, params, nct, 1, nct.length - 1, npt, 0);
                    javaDec.processBytes(jct, 1, jct.length - 1, jpt, 0);

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

//                    nativeDec.reset();
//                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }

    @Test
    public void testExceptions()
    {
        AESCTRModePacketCipher ctr = AESPacketCipherEngine.createCTRPacketCipher();
        try
        {
            ctr.getOutputSize(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
        }


        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

//        try
//        {
//            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[15], 0, 15, new byte[16], 0);
//            fail("output buffer too small for processPacket");
//        }
//        catch (PacketCipherException e)
//        {
//            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_DECRYPTION_INPUT_LENGTH_INVALID));
//        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            ctr.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            ctr.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }
}
