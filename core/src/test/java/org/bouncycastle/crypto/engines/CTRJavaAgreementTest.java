package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

public class CTRJavaAgreementTest extends TestCase
{

    @Before
    public void setUp()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    private void moveCtrToEnd(int ivLen, SkippingStreamCipher cipher) throws Exception
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
    public void testSeekingIntoFirstInvalidBlock() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR testSeekingIntoFirstInvalidBlock: " + TestUtil.errorMsg());
            }
            return;
        }


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
    public void testSpreadArray() throws Exception
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

                StreamCipher javaEnc =  new SICBlockCipher(new AESEngine());
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


                    nativeEnc.processBytes(msg, 0, msg.length, nct, 0);


                    javaEnc.processBytes(msg, 0, msg.length, jct, 0);

                    if (!Arrays.areEqual(jct, nct))
                    {
                        System.out.println(Hex.toHexString(jct));
                        System.out.println(Hex.toHexString(nct));
                    }

                    TestCase.assertTrue("Java CT = Native CT", Arrays.areEqual(jct, nct));

                    nativeDec.processBytes(nct, 0, nct.length, npt, 0);
                    javaDec.processBytes(jct, 0, jct.length, jpt, 0);


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
    public void testSpreadProcessBlocks() throws Exception
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
    public void testSpreadStreaming() throws Exception
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
    public void testOverflowBehaviorBlockWrite() throws Exception
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
                    javaEnc.returnByte((byte) 0);
                }


                try
                {
                    javaEnc.returnByte((byte) 0);
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
                    nativeEnc.returnByte((byte) 0);
                }


                try
                {
                    nativeEnc.returnByte((byte) 0);
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
                    javaEnc.returnByte((byte) 0);
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
                    nativeEnc.returnByte((byte) 0);
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
    public void testOverflowBehaviorBlockStream() throws Exception
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
                    javaEnc.returnByte((byte) 0); // Todo this may be a bug.
                }


                try
                {
                    javaEnc.returnByte((byte) 1);
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
                    nativeEnc.returnByte((byte) 1);
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
                    javaEnc.returnByte((byte) 1);
                }

                try
                {
                    javaEnc.returnByte((byte) 1); // should fail here
                }
                catch (Exception ex)
                {
                    javaException = true;
                }


                nativeEnc.skip(maxBytes);
                for (int j = 0; j < 16; j++)
                {
                    nativeEnc.returnByte((byte) 1);
                }

                try
                {
                    nativeEnc.returnByte((byte) 1); // bad
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
    public void testUnderflowNormal() throws Exception
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
                byte c = (byte) ssr.nextInt(256);
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

            if (!Arrays.areEqual(nct,jct)) {
                System.out.println(Hex.toHexString(nct));
                System.out.println(Hex.toHexString(jct));
            }


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
    public void testSpreadArrayWithOffsets() throws Exception
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
    public void testSpreadProcessBlocksWithOffsets() throws Exception
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
                        System.out.println("KeySize: "+key.length);
                        System.out.println("IVLEn: "+iv.length);
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

    /**
     * getPosition() at the one-past-the-last-block end position. The counter has wrapped there, so
     * the masked difference underlying the position reads as zero - the start of the stream. That is
     * the dangerous answer: a caller resuming with seekTo(getPosition() + n) would silently rewind
     * and reuse keystream. The true end offset is reported instead, or -1 for the 8/16 byte IV cases
     * where 2^68 bytes exceeds a long.
     */
    @Test
    public void testPositionAtEndOfCounter() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR testPositionAtEndOfCounter: " + TestUtil.errorMsg());
            }
            return;
        }

        for (int ivLen : new int[]{15, 14, 13, 12, 11, 10, 9, 8, 16})
        {
            AESNativeCTR ctr = new AESNativeCTR();
            ctr.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[ivLen]));

            moveCtrToEnd(ivLen, ctr);

            long pos = ctr.getPosition();

            TestCase.assertTrue("ivLen " + ivLen + ": end position must not read as the stream start",
                pos != 0);

            if (ivLen == 8 || ivLen == 16)
            {
                TestCase.assertEquals("ivLen " + ivLen + ": end offset exceeds a long", -1L, pos);
            }
            else
            {
                long maxBlock = 0;
                for (int j = 0; j < 16 - ivLen; j++)
                {
                    maxBlock <<= 8;
                    maxBlock |= 0xFF;
                }
                TestCase.assertEquals("ivLen " + ivLen + ": end offset", (maxBlock + 1) * 16, pos);
            }
        }
    }

    /**
     * getPosition() agreement between the pure-Java and native CTR engines at in-range positions.
     * testPositionAtEndOfCounter covers the end of the counter space only; the positions a caller
     * actually resumes from are the ones in the middle, and nothing asserted that the two engines
     * report the same offset there - or that they emit the same keystream once they have.
     * <p>
     * Full 16-byte IVs are given a low counter lane well away from its wrap. Java carries into the
     * high lane there and native wraps modulo 2^64, which is a real divergence but a separate one;
     * this test is about positions where the two are required to agree.
     */
    @Test
    public void testInRangePositionAgreement() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR testInRangePositionAgreement: " + TestUtil.errorMsg());
            }
            return;
        }

        long seed = System.currentTimeMillis();
        SecureRandom rand = new SecureRandom();
        rand.setSeed(seed);

        String because = " (seed " + seed + ")";

        for (int ivLen : new int[]{16, 15, 14, 13, 12, 11, 10, 9, 8})
        {
            for (int ks : new int[]{16, 24, 32})
            {
                byte[] key = new byte[ks];
                byte[] iv = new byte[ivLen];

                rand.nextBytes(key);
                rand.nextBytes(iv);

                if (ivLen == 16)
                {
                    // keep the low counter lane far from its wrap - see the javadoc
                    for (int i = 8; i != 16; i++)
                    {
                        iv[i] = 0;
                    }
                }

                CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);

                SkippingStreamCipher javaCtr = new SICBlockCipher(new AESEngine());
                SkippingStreamCipher nativeCtr = new AESNativeCTR();

                javaCtr.init(true, params);
                nativeCtr.init(true, params);

                String at = "ivLen " + ivLen + " keyLen " + ks + because;

                // one past the last byte the counter space can produce; reads have to stay inside
                // it, since running off the end is a range failure rather than a disagreement
                long spaceEnd;
                if (ivLen == 8 || ivLen == 16)
                {
                    spaceEnd = 1L << 45;            // 2^68 bytes really, capped to keep positions exact
                }
                else
                {
                    long maxBlock = 0;
                    for (int j = 0; j < 16 - ivLen; j++)
                    {
                        maxBlock <<= 8;
                        maxBlock |= 0xFF;
                    }
                    spaceEnd = (maxBlock + 1) * 16;
                }

                long lastBlockStart = spaceEnd - 16;

                long[] positions = new long[]{
                    0, 1, 15, 16, 17, 31, 4095,
                    (rand.nextLong() >>> 1) % spaceEnd,
                    lastBlockStart - 16, lastBlockStart - 1, lastBlockStart
                };

                for (long p : positions)
                {
                    if (p < 0 || p > lastBlockStart)
                    {
                        continue;
                    }

                    javaCtr.seekTo(p);
                    nativeCtr.seekTo(p);

                    TestCase.assertEquals("java seekTo(" + p + ") " + at, p, javaCtr.getPosition());
                    TestCase.assertEquals("native seekTo(" + p + ") " + at, p, nativeCtr.getPosition());

                    int len = 1 + rand.nextInt(64);
                    if (len > spaceEnd - p)
                    {
                        len = (int)(spaceEnd - p);
                    }

                    byte[] in = new byte[len];
                    rand.nextBytes(in);

                    byte[] javaOut = new byte[len];
                    byte[] nativeOut = new byte[len];

                    javaCtr.processBytes(in, 0, len, javaOut, 0);
                    nativeCtr.processBytes(in, 0, len, nativeOut, 0);

                    TestCase.assertTrue("keystream at " + p + " " + at,
                        Arrays.areEqual(javaOut, nativeOut));
                    TestCase.assertEquals("position after " + len + " bytes from " + p + " " + at,
                        javaCtr.getPosition(), nativeCtr.getPosition());
                }

                // a random walk of signed skips, kept clear of both ends of the counter space
                int readLen = 24;
                long walkCeiling = spaceEnd - readLen;

                javaCtr.seekTo(0);
                nativeCtr.seekTo(0);

                long expected = 0;

                for (int step = 0; step != 200; step++)
                {
                    long delta = rand.nextInt(4096) - 2048;

                    if (expected + delta < 0 || expected + delta > walkCeiling)
                    {
                        delta = -delta;
                    }
                    if (expected + delta < 0 || expected + delta > walkCeiling)
                    {
                        continue;
                    }

                    javaCtr.skip(delta);
                    nativeCtr.skip(delta);
                    expected += delta;

                    TestCase.assertEquals("java walk step " + step + " " + at, expected, javaCtr.getPosition());
                    TestCase.assertEquals("native walk step " + step + " " + at, expected, nativeCtr.getPosition());

                    if (step % 10 == 0)
                    {
                        byte[] in = new byte[readLen];
                        rand.nextBytes(in);

                        byte[] javaOut = new byte[readLen];
                        byte[] nativeOut = new byte[readLen];

                        javaCtr.processBytes(in, 0, readLen, javaOut, 0);
                        nativeCtr.processBytes(in, 0, readLen, nativeOut, 0);

                        TestCase.assertTrue("keystream at walk step " + step + " " + at,
                            Arrays.areEqual(javaOut, nativeOut));

                        expected += readLen;

                        TestCase.assertEquals("position after walk read " + step + " " + at,
                            expected, nativeCtr.getPosition());
                    }
                }
            }
        }
    }

    // AES-ECB of the counter block the spec asks for at blockIndex: IV + blockIndex over the full
    // 128 bits. Neither engine is involved, so a block can be checked without assuming either is right.
    private byte[] referenceBlock(byte[] key, byte[] iv, long blockIndex)
    {
        BigInteger counter = new BigInteger(1, iv)
            .add(BigInteger.valueOf(blockIndex))
            .mod(BigInteger.ONE.shiftLeft(128));

        byte[] raw = counter.toByteArray();
        byte[] block = new byte[16];
        int copy = Math.min(16, raw.length);
        System.arraycopy(raw, raw.length - copy, block, 16 - copy, copy);

        AESEngine ecb = new AESEngine();
        ecb.init(true, new KeyParameter(key));

        byte[] out = new byte[16];
        ecb.processBlock(block, 0, out, 0);

        return out;
    }

    /**
     * A full 16-byte IV makes the whole block the counter, so once the low 8-byte lane runs out it
     * has to carry into the high one. Java did; native froze the high lane at init and wrapped the
     * low lane modulo 2^64, so from the wrap onward the two produced different keystream for the
     * same key and IV while getPosition() agreed on both - encrypting on one and decrypting on the
     * other corrupted silently. The wide native paths add block offsets into the low lane only, so
     * the crossing is stepped over one block at a time.
     */
    @Test
    public void testFullIVLowLaneWrapAgreement() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("ctr"))
            {
                TestCase.fail("Skipping CTR testFullIVLowLaneWrapAgreement: " + TestUtil.errorMsg());
            }
            return;
        }

        long seed = System.currentTimeMillis();
        SecureRandom rand = new SecureRandom();
        rand.setSeed(seed);

        // high lane fixed, low lane placed so the wrap lands at block 1, block 8, and never
        String[] ivs = new String[]{
            "0011223344556677FFFFFFFFFFFFFFFF",     // wraps after 1 block
            "0011223344556677FFFFFFFFFFFFFFF8",     // wraps after 8 blocks
            "0011223344556677FFFFFFFF00000000"      // control, no wrap in range
        };
        long[] wrapAt = new long[]{1, 8, -1};

        // chunkings drive different dispatcher paths, which is where a missed step shows up
        int[] chunks = new int[]{64 * 16, 16, 1, 15, 17, 4 * 16};

        int blocks = 64;
        int total = blocks * 16;

        for (int v = 0; v != ivs.length; v++)
        {
            byte[] iv = Hex.decode(ivs[v]);

            for (int ks : new int[]{16, 24, 32})
            {
                byte[] key = new byte[ks];
                rand.nextBytes(key);

                CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
                String at = "iv " + ivs[v] + " keyLen " + ks + " (seed " + seed + ")";

                byte[] in = new byte[total];
                rand.nextBytes(in);

                SkippingStreamCipher javaCtr = new SICBlockCipher(new AESEngine());
                javaCtr.init(true, params);

                byte[] javaOut = new byte[total];
                javaCtr.processBytes(in, 0, total, javaOut, 0);

                // the Java path is itself checked against the spec, so a shared error cannot hide here
                if (wrapAt[v] > 0)
                {
                    long past = wrapAt[v] + 2;
                    byte[] expect = referenceBlock(key, iv, past);
                    byte[] actual = new byte[16];
                    for (int i = 0; i != 16; i++)
                    {
                        actual[i] = (byte)(javaOut[(int)past * 16 + i] ^ in[(int)past * 16 + i]);
                    }
                    TestCase.assertTrue("java block " + past + " past the wrap " + at,
                        Arrays.areEqual(expect, actual));
                }

                for (int c = 0; c != chunks.length; c++)
                {
                    SkippingStreamCipher nativeCtr = new AESNativeCTR();
                    nativeCtr.init(true, params);

                    byte[] nativeOut = new byte[total];

                    int done = 0;
                    while (done < total)
                    {
                        int n = Math.min(chunks[c], total - done);
                        nativeCtr.processBytes(in, done, n, nativeOut, done);
                        done += n;
                    }

                    TestCase.assertTrue("keystream chunk " + chunks[c] + " " + at,
                        Arrays.areEqual(javaOut, nativeOut));
                    TestCase.assertEquals("position chunk " + chunks[c] + " " + at,
                        (long)total, nativeCtr.getPosition());
                }

                if (wrapAt[v] < 0)
                {
                    continue;
                }

                // seek straight past the wrap, then walk back over it and out again
                long past = (wrapAt[v] + 3) * 16;
                long before = (wrapAt[v] - 1) * 16;

                SkippingStreamCipher nativeCtr = new AESNativeCTR();
                nativeCtr.init(true, params);
                javaCtr.seekTo(past);
                nativeCtr.seekTo(past);

                byte[] jb = new byte[16];
                byte[] nb = new byte[16];

                javaCtr.processBytes(in, 0, 16, jb, 0);
                nativeCtr.processBytes(in, 0, 16, nb, 0);

                TestCase.assertTrue("keystream after seek past the wrap " + at, Arrays.areEqual(jb, nb));
                TestCase.assertEquals("position after seek past the wrap " + at,
                    javaCtr.getPosition(), nativeCtr.getPosition());

                // back across the wrap - the carry has to be given back
                javaCtr.seekTo(before);
                nativeCtr.seekTo(before);

                javaCtr.processBytes(in, 0, 16, jb, 0);
                nativeCtr.processBytes(in, 0, 16, nb, 0);

                TestCase.assertTrue("keystream back before the wrap " + at, Arrays.areEqual(jb, nb));

                // and forward over it once more from there
                javaCtr.skip(32);
                nativeCtr.skip(32);

                javaCtr.processBytes(in, 0, 16, jb, 0);
                nativeCtr.processBytes(in, 0, 16, nb, 0);

                TestCase.assertTrue("keystream forward over the wrap again " + at, Arrays.areEqual(jb, nb));
                TestCase.assertEquals("position forward over the wrap again " + at,
                    javaCtr.getPosition(), nativeCtr.getPosition());
            }
        }
    }

}
