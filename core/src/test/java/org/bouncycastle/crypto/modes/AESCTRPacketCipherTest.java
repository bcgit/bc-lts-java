package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCTR;
import org.bouncycastle.crypto.engines.StreamingFixedSecureRandom;
import org.bouncycastle.crypto.engines.TestUtil;
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
        test.testSpreadArray();
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

        AESCTRPacketCipher ctrPC = AESCTRPacketCipher.makeInstance();
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

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }


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

                AESNativeCTR nativeEnc = new AESNativeCTR();
                nativeEnc.init(true, params);

                AESNativeCTR nativeDec = new AESNativeCTR();
                nativeDec.init(false, params);

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

                    nativeEnc.processBlocks(msg, 0, msg.length / 16, nct, 0);
                    javaEnc.processBlocks(msg, 0, msg.length / 16, jct, 0);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    nativeDec.processBlocks(nct, 0, nct.length / 16, npt, 0);
                    javaDec.processBlocks(jct, 0, jct.length / 16, jpt, 0);

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

                    nativeDec.reset();
                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }


    @Test
    public void testSpreadStreaming()
        throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread streaming test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom rand = new SecureRandom();

        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);


            for (int ivLen : new int[]{15, 14, 13, 12, 11, 10, 9, 8})
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);

                ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

                AESNativeCTR nativeEnc = new AESNativeCTR();
                nativeEnc.init(true, params);

                AESNativeCTR nativeDec = new AESNativeCTR();
                nativeDec.init(false, params);

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
                    byte[] nct = new byte[l];
                    byte[] npt = new byte[l];
                    byte[] jct = new byte[l];
                    byte[] jpt = new byte[l];

                    rand.nextBytes(msg);


                    for (int t = 0; t < msg.length; t++)
                    {
                        nct[t] = nativeEnc.returnByte(msg[t]);
                        jct[t] = javaEnc.returnByte(msg[t]);
                    }


                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));


                    for (int t = 0; t < nct.length; t++)
                    {
                        npt[t] = nativeDec.returnByte(nct[t]);
                        jpt[t] = javaDec.returnByte(jct[t]);
                    }

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

                    nativeDec.reset();
                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }

    @Test
    public void testOverflowBehaviorBlockWrite()
        throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        byte[] key = new byte[16];
        rand.nextBytes(key);

        int[] ivLens = new int[]{15, 14, 13, 12, 11, 10, 9, 8};
        long[] maxBlk = new long[]{1, 2, 3, 4, 5, 6, 7, 8};

        for (int t = 0; t < ivLens.length; t++)
        {
            int ivLen = ivLens[t];

            byte[] iv = new byte[ivLen];
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            boolean javaException = false;
            boolean nativeException = false;


            if (ivLen == 8)
            {
                //
                // This is a special case where the two implementations diverge.
                //

                for (int j = 0; j < 32; j++)
                {
                    javaEnc.skip(Long.MAX_VALUE);
                    javaEnc.returnByte((byte)0);
                }


                try
                {
                    javaEnc.returnByte((byte)0);
                }
                catch (Exception ex)
                {
                    javaException = true;
                }


                //
                // Crank the ctr forward.
                //
                for (int j = 0; j < 32; j++)
                {
                    nativeEnc.skip(Long.MAX_VALUE);
                }


                for (int j = 0; j < 32; j++)
                {
                    nativeEnc.returnByte((byte)0);
                }


                try
                {
                    nativeEnc.returnByte((byte)0);
                }
                catch (Exception ex)
                {
                    nativeException = true;
                }

                TestCase.assertTrue("16 byte overflow", nativeException);
                TestCase.assertTrue("16 byte iv overflow ", javaException);
            }
            else
            {
                long maxBlock = 0;
                for (int j = 0; j < maxBlk[t]; j++)
                {
                    maxBlock <<= 8;
                    maxBlock |= 0xFF;
                }


                long maxBytes = maxBlock * 16;


                try
                {
                    javaEnc.skip(maxBytes - 1);
                    javaEnc.skip(1);
                    javaEnc.processBlock(new byte[16], 0, new byte[16], 0);
                    javaEnc.returnByte((byte)0);
                }
                catch (Exception ex)
                {
                    javaException = true;
                }

                try
                {
                    nativeEnc.skip(maxBytes - 1);
                    nativeEnc.skip(1);
                    nativeEnc.processBlock(new byte[16], 0, new byte[16], 0);
                    nativeEnc.returnByte((byte)0);
                }
                catch (Exception ex)
                {
                    nativeException = true;
                }

                TestCase.assertTrue(ivLen + " byte iv overflow ", javaException);
                TestCase.assertTrue(ivLen + " byte iv overflow ", nativeException);

            }


        }


    }

    @Test
    public void testOverflowBehaviorBlockStream()
        throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR stream overflow block test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        byte[] key = new byte[16];
        rand.nextBytes(key);

        int[] ivLens = new int[]{15, 14, 13, 12, 11, 10, 9, 8};
        long[] maxBlk = new long[]{1, 2, 3, 4, 5, 6, 7, 8};

        for (int t = 0; t < ivLens.length; t++)
        {
            int ivLen = ivLens[t];

            byte[] iv = new byte[ivLen];
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            boolean javaException = false;
            boolean nativeException = false;


            if (ivLen == 8)
            {
                //
                // This is a special case where the two implementations diverge.
                //
                //

                //
                // Crank the ctr forward.
                //
                for (int j = 0; j < 32; j++)
                {
                    javaEnc.skip(Long.MAX_VALUE);
                    javaEnc.returnByte((byte)0); // Todo this may be a bug.
                }


                try
                {
                    javaEnc.returnByte((byte)1);
                }
                catch (Exception ex)
                {
                    javaException = true;
                }


                //
                // Crank the ctr forward.
                //
                for (int j = 0; j < 32; j++)
                {
                    nativeEnc.skip(Long.MAX_VALUE);
                    nativeEnc.skip(1);
                }

                try
                {
                    nativeEnc.returnByte((byte)1);
                }
                catch (Exception ex)
                {
                    nativeException = true;
                }

                TestCase.assertTrue("16 byte overflow", nativeException);
                TestCase.assertTrue("16 byte iv overflow ", javaException);
            }
            else
            {
                long maxBlock = 0;
                for (int j = 0; j < maxBlk[t]; j++)
                {
                    maxBlock <<= 8;
                    maxBlock |= 0xFF;
                }

                long maxBytes = maxBlock * 16;


                javaEnc.skip(maxBytes);

                for (int j = 0; j < 16; j++)
                {
                    javaEnc.returnByte((byte)1);
                }

                try
                {
                    javaEnc.returnByte((byte)1); // should fail here
                }
                catch (Exception ex)
                {
                    javaException = true;
                }


                nativeEnc.skip(maxBytes);
                for (int j = 0; j < 16; j++)
                {
                    nativeEnc.returnByte((byte)1);
                }

                try
                {
                    nativeEnc.returnByte((byte)1); // bad
                }
                catch (Exception ex)
                {
                    nativeException = true;
                }

                TestCase.assertTrue(ivLen + " byte iv overflow ", nativeException && javaException);

            }

        }

    }

    @Test
    public void testUnderflowNormal()
        throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("normal underflow test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        byte[] key = new byte[16];
        rand.nextBytes(key);

        int[] ivLens = new int[]{16, 15, 14, 13, 12, 11, 10, 9, 8};


        for (int t = 0; t < ivLens.length; t++)
        {
            int ivLen = ivLens[t];

            byte[] iv = new byte[ivLen];
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            boolean javaException = false;
            boolean nativeException = false;


            if (ivLen == 16)
            {
                javaException = true;
            }
            else
            {

                try
                {
                    javaEnc.skip(-1);
                }
                catch (Exception ex)
                {
                    javaException = true;
                }
            }

            try
            {
                nativeEnc.skip(-1);
            }
            catch (Exception ex)
            {
                nativeException = true;
            }

            TestCase.assertTrue(ivLen + " byte iv underflow ", nativeException && javaException);

        }
    }

    @Test
    public void testSeekMonte()
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR stream overflow block test: " + TestUtil.errorMsg());
            }
            return;
        }

        byte[] seed = new byte[10];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(seed);

        // Copy seed value from error report to this and uncomment to
        // reproduce the same series of operations with the same values.

        // seed = Hex.decode("174343ccc52983b997f8");

        StreamingFixedSecureRandom ssr = new StreamingFixedSecureRandom(seed);


        byte[] key = new byte[16];
        ssr.nextBytes(key);

        int[] ivLens = new int[]{16, 15, 14, 13, 12, 11, 10, 9, 8};
        long[] maxBlk = new long[]{16, 1, 2, 3, 4, 5, 6, 7, 8};

        for (int t = 0; t < ivLens.length; t++)
        {
            int ivLen = ivLens[t];

            byte[] iv = new byte[ivLen];
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            long maxBlock = 0;
            for (int j = 0; j < maxBlk[t]; j++)
            {
                maxBlock <<= 8;
                maxBlock |= 0xFF;
            }


            for (int r = 0; r < 10000; r++)
            {
                long s = ssr.nextLong() & maxBlock;
                if (s < 0)
                {
                    s *= -1;
                }
                javaEnc.seekTo(s);
                nativeEnc.seekTo(s);
                byte c = (byte)ssr.nextInt(256);
                byte j0 = javaEnc.returnByte(c);
                byte n0 = nativeEnc.returnByte(c);

                TestCase.assertEquals("Iv len: " + ivLen + " pos " + s + " seek test not equal", j0, n0);
            }


            if (ivLen != 16 && ivLen != 8)
            {
                try
                {
                    javaEnc.seekTo(maxBlock * 16 + 1);
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("out of range"));
                }

                try
                {
                    nativeEnc.seekTo(maxBlock * 16 + 1);
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("out of range"));
                }
            }

        }

    }

    @Test
    public void testIVReplacement()
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[10];
        rand.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);


            // set up with key

            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);


            ParametersWithIV paramsNoKey = new ParametersWithIV(null, iv);


            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            AESNativeCTR nativeDec = new AESNativeCTR();
            nativeDec.init(false, params);

            SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
            javaDec.init(false, params);


            byte[] msg = new byte[17];
            rand.nextBytes(msg);

            byte[] jct = new byte[msg.length];
            byte[] nct = new byte[msg.length];

            nativeEnc.processBytes(msg, 0, msg.length, nct, 0);
            javaEnc.processBytes(msg, 0, msg.length, jct, 0);

            TestCase.assertTrue(Arrays.areEqual(nct, jct));


            byte[] jpt = new byte[msg.length];
            byte[] npt = new byte[msg.length];


            nativeDec.processBytes(nct, 0, nct.length, npt, 0);
            javaDec.processBytes(jct, 0, jct.length, jpt, 0);

            TestCase.assertTrue(Arrays.areEqual(npt, jpt));
            TestCase.assertTrue(Arrays.areEqual(msg, jpt));


            //
            // Change IV to the same iv, results should still be the same.
            //

            nativeEnc.init(true, paramsNoKey);
            javaEnc.init(true, paramsNoKey);
            nativeDec.init(false, paramsNoKey);
            javaDec.init(false, paramsNoKey);


            byte[] msg1 = msg;


            byte[] jct1 = new byte[msg.length];
            byte[] nct1 = new byte[msg.length];

            nativeEnc.processBytes(msg1, 0, msg1.length, nct1, 0);
            javaEnc.processBytes(msg1, 0, msg1.length, jct1, 0);

            TestCase.assertTrue(Arrays.areEqual(nct1, jct1));
            TestCase.assertTrue(Arrays.areEqual(nct1, jct)); // from first round


            byte[] jpt1 = new byte[msg1.length];
            byte[] npt1 = new byte[msg1.length];


            nativeDec.processBytes(nct1, 0, nct1.length, npt1, 0);
            javaDec.processBytes(jct1, 0, jct1.length, jpt1, 0);

            TestCase.assertTrue(Arrays.areEqual(npt1, jpt1));
            TestCase.assertTrue(Arrays.areEqual(msg1, jpt1));


            //
            // Change to a different IV, results will be different.
            //

            rand.nextBytes(iv);

            ParametersWithIV paramsNew = new ParametersWithIV(null, iv);
            nativeEnc.init(true, paramsNew);
            javaEnc.init(true, paramsNew);
            nativeDec.init(false, paramsNew);
            javaDec.init(false, paramsNew);


            jct1 = new byte[msg.length];
            nct1 = new byte[msg.length];

            nativeEnc.processBytes(msg, 0, msg.length, nct1, 0);
            javaEnc.processBytes(msg, 0, msg.length, jct1, 0);

            TestCase.assertTrue(Arrays.areEqual(nct1, jct1));
            TestCase.assertFalse(Arrays.areEqual(nct1, jct)); // different to first round


            jpt1 = new byte[msg.length];
            npt1 = new byte[msg.length];


            nativeDec.processBytes(nct1, 0, nct1.length, npt1, 0);
            javaDec.processBytes(jct1, 0, jct1.length, jpt1, 0);

            TestCase.assertTrue(Arrays.areEqual(npt1, jpt1));
            TestCase.assertTrue(Arrays.areEqual(msg, jpt1));


        }
    }

    @Test
    public void testBlock()
    {

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[10];
        rand.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);


            // set up with key

            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);


            ParametersWithIV paramsNoKey = new ParametersWithIV(null, iv);


            AESNativeCTR nativeEnc = new AESNativeCTR();
            nativeEnc.init(true, params);

            SICBlockCipher javaEnc = new SICBlockCipher(new AESEngine());
            javaEnc.init(true, params);

            AESNativeCTR nativeDec = new AESNativeCTR();
            nativeDec.init(false, params);

            SICBlockCipher javaDec = new SICBlockCipher(new AESEngine());
            javaDec.init(false, params);


            byte[] msg = new byte[16];
            rand.nextBytes(msg);

            byte[] jct = new byte[msg.length];
            byte[] nct = new byte[msg.length];

            nativeEnc.processBlock(msg, 0, nct, 0);
            javaEnc.processBlock(msg, 0, jct, 0);

            TestCase.assertTrue(Arrays.areEqual(nct, jct));


            byte[] jpt = new byte[msg.length];
            byte[] npt = new byte[msg.length];


            nativeDec.processBlock(nct, 0, npt, 0);
            javaDec.processBlock(jct, 0, jpt, 0);

            TestCase.assertTrue(Arrays.areEqual(npt, jpt));
            TestCase.assertTrue(Arrays.areEqual(msg, jpt));

        }
    }


    @Test
    public void testSpreadArrayWithOffsets()
        throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }


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

                AESNativeCTR nativeEnc = new AESNativeCTR();
                nativeEnc.init(true, params);

                AESNativeCTR nativeDec = new AESNativeCTR();
                nativeDec.init(false, params);

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

                    nativeEnc.processBytes(msg, 0, msg.length, nct, 1);
                    javaEnc.processBytes(msg, 0, msg.length, jct, 1);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    nativeDec.processBytes(nct, 1, nct.length - 1, npt, 0);
                    javaDec.processBytes(jct, 1, jct.length - 1, jpt, 0);

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

                    nativeDec.reset();
                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }


    @Test
    public void testSpreadProcessBlocksWithOffsets()
        throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR spread test: " + TestUtil.errorMsg());
            }
            return;
        }


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

                AESNativeCTR nativeEnc = new AESNativeCTR();
                nativeEnc.init(true, params);

                AESNativeCTR nativeDec = new AESNativeCTR();
                nativeDec.init(false, params);

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
                    byte[] nct = new byte[l + 1];
                    byte[] npt = new byte[l];
                    byte[] jct = new byte[l + 1];
                    byte[] jpt = new byte[l];

                    rand.nextBytes(msg);

                    nativeEnc.processBlocks(msg, 0, msg.length / 16, nct, 1);
                    javaEnc.processBlocks(msg, 0, msg.length / 16, jct, 1);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    nativeDec.processBlocks(nct, 1, (nct.length - 1) / 16, npt, 0);
                    javaDec.processBlocks(jct, 1, (jct.length - 1) / 16, jpt, 0);

                    TestCase.assertTrue("Java PT = Native PT", Arrays.areEqual(jpt, npt));

                    TestCase.assertTrue("Native PT matches original message ", Arrays.areEqual(msg, npt));

                    nativeDec.reset();
                    nativeEnc.reset();
                    javaDec.reset();
                    javaEnc.reset();

                }
            }
        }
    }
}
