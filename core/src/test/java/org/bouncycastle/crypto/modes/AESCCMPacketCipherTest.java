package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCCMPacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


public class AESCCMPacketCipherTest
    extends TestCase
{
    private byte[] K1 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N1 = Hex.decode("10111213141516");
    private byte[] A1 = Hex.decode("0001020304050607");
    private byte[] P1 = Hex.decode("20212223");
    private byte[] C1 = Hex.decode("7162015b4dac255d");
    private byte[] T1 = Hex.decode("6084341b");

    private byte[] K2 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N2 = Hex.decode("1011121314151617");
    private byte[] A2 = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private byte[] P2 = Hex.decode("202122232425262728292a2b2c2d2e2f");
    private byte[] C2 = Hex.decode("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd");
    private byte[] T2 = Hex.decode("7f479ffca464");

    private byte[] K3 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N3 = Hex.decode("101112131415161718191a1b");
    private byte[] A3 = Hex.decode("000102030405060708090a0b0c0d0e0f10111213");
    private byte[] P3 = Hex.decode("202122232425262728292a2b2c2d2e2f3031323334353637");
    private byte[] C3 = Hex.decode("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951");
    private byte[] T3 = Hex.decode("67c99240c7d51048");

    private byte[] K4 = Hex.decode("404142434445464748494a4b4c4d4e4f");
    private byte[] N4 = Hex.decode("101112131415161718191a1b1c");
    //private byte[] A4 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9caccmccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private byte[] P4 = Hex.decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private byte[] C4 = Hex.decode("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");
    private byte[] T4 = Hex.decode("f4dd5d0ee404617225ffe34fce91");

    //
    // long data vector
    //
    private byte[] C5 = Hex.decode("49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3fa5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa8071e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb141d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e854fd3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2dca128f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b51c07beb40e875a87491ec8b27cd1");
    private byte[] T5 = Hex.decode("5c768856796b627b13ec8641581b");

    public void performTest()
        throws Exception
    {
        testAgreementForMultipleMessages();
        testIntoSameArray();
        CryptoServicesRegistrar.setNativeEnabled(true);
        Tests();
        CryptoServicesRegistrar.setNativeEnabled(false);
        Tests();
    }

    public void Tests()
        throws Exception
    {

        AESCCMModePacketCipher ccm = AESPacketCipherEngine.createCCMPacketCipher();

        checkVectors(0, ccm, K1, 32, N1, A1, P1, T1, C1);
        checkVectors(1, ccm, K2, 48, N2, A2, P2, T2, C2);
        checkVectors(2, ccm, K3, 64, N3, A3, P3, T3, C3);

        //
        // 4 has a reduced associated text which needs to be replicated
        //
//        byte[] a4 = new byte[65536]; // 524288 / 8

//        for (int i = 0; i < a4.length; i += A4.length)
//        {
//            System.arraycopy(A4, 0, a4, i, A4.length);
//        }
//
//        checkVectors(3, ccm, K4, 112, N4, a4, P4, T4, C4);
//
//        //
//        // long data test
//        //
//        checkVectors(4, ccm, K4, 112, N4, A4, A4, T5, C5);
        testExceptions();
        testOutputErase();
        testAgreement();
        testCCMSpreadAgreement();
    }

    private void testAgreement()
        throws InvalidCipherTextException, PacketCipherException
    {
        SecureRandom secureRandom = new SecureRandom();
        AESCCMModePacketCipher ccm2 = AESPacketCipherEngine.createCCMPacketCipher();
        int[] keybytes = {16, 24, 32};
        for (int i = 0; i < 3; ++i)
        {
            int keySize = keybytes[i];

            for (int t = 0; t < 4000; t++)
            {
                byte[] javaPT = new byte[secureRandom.nextInt(2048)];
                secureRandom.nextBytes(javaPT);
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);

                byte[] iv = new byte[13];
                secureRandom.nextBytes(iv);
                CCMBlockCipher ccm1 = new CCMBlockCipher(new AESEngine());
                ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
                ccm1.init(true, parameters);
                byte[] ccm1CT = new byte[ccm1.getOutputSize(javaPT.length)];
                int j = ccm1.processBytes(javaPT, 0, javaPT.length, ccm1CT, 0);
                ccm1.doFinal(ccm1CT, j);

                byte[] ccm2CT = new byte[ccm2.getOutputSize(true, parameters, javaPT.length)];
                ccm2.processPacket(true, parameters, javaPT, 0, javaPT.length, ccm2CT, 0);

                if (!Arrays.areEqual(ccm1CT, ccm2CT))
                {
                    System.out.println(javaPT.length);
                    System.out.println(Hex.toHexString(ccm2CT));
                    System.out.println(Hex.toHexString(ccm1CT));
                    for (j = 0; j < ccm2CT.length; j++)
                    {
                        if (ccm2CT[j] == ccm1CT[j])
                        {
                            System.out.print("  ");
                        }
                        else
                        {
                            System.out.print("^^");
                        }
                    }
                    System.out.println();
                }

                ccm1.init(true, parameters);
                byte[] ccm1PT = new byte[ccm1.getOutputSize(ccm1CT.length)];
                j = ccm1.processBytes(ccm1CT, 0, ccm1CT.length, ccm1PT, 0);
                ccm1.doFinal(ccm1PT, j);

                byte[] ccm2PT = new byte[ccm2.getOutputSize(true, parameters, ccm2CT.length)];
                ccm2.processPacket(true, parameters, ccm2CT, 0, ccm2CT.length, ccm2PT, 0);

                if (!Arrays.areEqual(ccm1PT, ccm2PT))
                {
                    System.out.println(javaPT.length);
                    System.out.println(Hex.toHexString(ccm1PT));
                    System.out.println(Hex.toHexString(ccm2PT));
                    for (j = 0; j < ccm2CT.length; j++)
                    {
                        if (ccm2PT[j] == ccm1PT[j])
                        {
                            System.out.print("  ");
                        }
                        else
                        {
                            System.out.print("^^");
                        }
                    }
                    System.out.println();
                }
            }
        }

    }

    public void testCCMSpreadAgreement()
        throws Exception
    {

//        if (!TestUtil.hasNativeService("AES/CCM"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("ccm"))
//            {
//                TestCase.fail("Skipping CCM Spread Agreement: " + TestUtil.errorMsg());
//            }
//            return;
//        }

        SecureRandom rand = new SecureRandom();
        SecureRandom secureRandom = new SecureRandom();
        AESCCMModePacketCipher ccm2 = AESPacketCipherEngine.createCCMPacketCipher();
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            for (int ivLen = 7; ivLen <= 13; ivLen++)
            {
                byte[] iv = new byte[ivLen];
                rand.nextBytes(iv);


                for (int macSize = 32; macSize <= 128; macSize += 16)
                {

                    for (int msgSize = 0; msgSize < 515; msgSize++)
                    {

                        byte[] javaPT;
                        if (msgSize != 0)
                        {
                            javaPT = new byte[secureRandom.nextInt(msgSize)];
                        }
                        else
                        {
                            javaPT = new byte[0];
                        }


                        CCMBlockCipher ccm1 = new CCMBlockCipher(new AESEngine());
                        AEADParameters parameters = new AEADParameters(new KeyParameter(key), macSize, iv);
                        ccm1.init(true, parameters);
                        byte[] ccm1CT = new byte[ccm1.getOutputSize(javaPT.length)];
                        int j = ccm1.processBytes(javaPT, 0, javaPT.length, ccm1CT, 0);
                        ccm1.doFinal(ccm1CT, j);

                        byte[] ccm2CT = new byte[ccm2.getOutputSize(true, parameters, javaPT.length)];
                        ccm2.processPacket(true, parameters, javaPT, 0, javaPT.length, ccm2CT, 0);

                        if (!Arrays.areEqual(ccm1CT, ccm2CT))
                        {
                            System.out.println(javaPT.length);
                            System.out.println(Hex.toHexString(ccm2CT));
                            System.out.println(Hex.toHexString(ccm1CT));
                            for (j = 0; j < ccm2CT.length; j++)
                            {
                                if (ccm2CT[j] == ccm1CT[j])
                                {
                                    System.out.print("  ");
                                }
                                else
                                {
                                    System.out.print("^^");
                                }
                            }
                            System.out.println();
                        }

                    }
                }
            }

        }
    }

    private void checkVectors(
        int count,
        AESCCMModePacketCipher ccm,
        byte[] k,
        int macSize,
        byte[] n,
        byte[] a,
        byte[] p,
        byte[] t,
        byte[] c)
        throws PacketCipherException
    {
        KeyParameter keyParam = (k == null) ? null : new KeyParameter(k);
        AEADParameters parameters = new AEADParameters(keyParam, macSize, n, a);
        int len = ccm.getOutputSize(true, parameters, p.length);
        byte[] enc = new byte[len];
        ccm.processPacket(true, parameters, p, 0, p.length, enc, 0);

        if (!Arrays.areEqual(c, enc))
        {
            for (int i = 0; i < c.length; ++i)
            {
                if (c[i] != enc[i])
                {
                    System.out.println(i + " " + c[i] + enc[i]);
                }
            }
            fail("encrypted stream fails to match in test " + count);
        }

        len = ccm.getOutputSize(false, parameters, enc.length);
        byte[] dec = new byte[len];
        ccm.processPacket(false, parameters, enc, 0, enc.length, dec, 0);

        TestCase.assertTrue("decrypted stream fails to match in test " + count, Arrays.areEqual(p, dec));
    }

    public void testOutputErase()
    {
        AESCCMModePacketCipher ccm = AESPacketCipherEngine.createCCMPacketCipher();
        byte[] C3new = Arrays.clone(C3);
        C3new[0]++;
        KeyParameter keyParam = (K3 == null) ? null : new KeyParameter(K3);
        AEADParameters parameters = new AEADParameters(keyParam, 64, N3, A3);
        int len = ccm.getOutputSize(false, parameters, C3new.length) + C3new.length;
        byte[] dec = new byte[len];
        System.arraycopy(C3new, 0, dec, 0, C3new.length);
        byte[] origin = Arrays.clone(dec);

        try
        {
            ccm.processPacket(false, parameters, dec, 0, dec.length, dec, C3new.length);
            fail("mac check should be false");
        }
        catch (PacketCipherException e)
        {
            if (!Arrays.areEqual(origin, dec))
            {
                fail("the Output Erase is wrong");
            }
        }
    }

    public void testExceptions()
    {
        AESCCMModePacketCipher ccm = AESPacketCipherEngine.createCCMPacketCipher();
        try
        {
            ccm.getOutputSize(false, new KeyParameter(new byte[16]), 0);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains("invalid parameters passed to CCM"));
        }

        try
        {
            ccm.getOutputSize(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[13]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertEquals("wrong message", ExceptionMessage.LEN_NEGATIVE, e.getMessage());
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[18]), 128, new byte[12]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[14]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains("nonce must have length from 7 to 13 octets"));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 127, new byte[16]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid mac size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains("tag length in octets must be one of {4,6,8,10,12,14,16}"));
        }

        try
        {
            ccm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), null, 0, 0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[16], 0, 16, new byte[17], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[16], -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[16], 0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            ccm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[16], 0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ccm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[15], 0, 15, new byte[0], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_SHORT));
        }

        try
        {
            ccm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]), new byte[17], 0, 17, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }

    public boolean isNativeVariant()
    {
        String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
        if (variant == null || "java".equals(variant))
        {
            return false;
        }
        return true;
    }

    public void testAgreementForMultipleMessages()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        CryptoServicesRegistrar.setNativeEnabled(false);

        // Java implementation of CCM mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CCMModeCipher ccmModeCipherEnc = new CCMBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        CryptoServicesRegistrar.setNativeEnabled(true);
        PacketCipher ccmPS = AESCCMPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(ccmPS.toString().contains("CCM-PS[Native]"));
            TestCase.assertTrue(ccmPS instanceof AESNativeCCMPacketCipher);
        }
        else
        {
            TestCase.assertTrue(ccmPS.toString().contains("CCM-PS[Java]"));
            TestCase.assertTrue(ccmPS instanceof AESCCMPacketCipher);
        }

        byte[] iv = new byte[7];
        secureRandom.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
            ccmModeCipherEnc.init(true, cp);


            for (int t = 0; t < 8192; t += 16)
            {
                ccmModeCipherEnc.reset();
                byte[] msg = new byte[t];
                secureRandom.nextBytes(msg);

                // Generate expected message off the
                int outLen = ccmModeCipherEnc.getOutputSize(msg.length);
                byte[] expected = new byte[ccmModeCipherEnc.getOutputSize(msg.length)];
                ccmModeCipherEnc.processPacket(msg, 0, msg.length, expected, 0);


                // Test encryption
                int len = ccmPS.getOutputSize(true, cp, msg.length);
                TestCase.assertEquals(outLen, len);
                byte[] ctResult = new byte[len];

                outLen = ccmPS.processPacket(true, cp, msg, 0, msg.length, ctResult, 0);
                TestCase.assertEquals(ctResult.length, outLen);

                // Test encrypted output same
                TestCase.assertTrue(Arrays.areEqual(expected, ctResult));


                // Test decryption

                len = ccmPS.getOutputSize(false, cp, ctResult.length);
                TestCase.assertEquals(msg.length, len);
                byte[] ptResult = new byte[len];

                outLen = ccmPS.processPacket(false, cp, ctResult, 0, ctResult.length, ptResult, 0);
                TestCase.assertEquals(msg.length, outLen);

                // Test encrypted output same
                TestCase.assertTrue(Arrays.areEqual(msg, ptResult));

            }
        }
    }


    /**
     * Tests operation of packet cipher where input and output arrays are the same
     *
     * @throws Exception
     */
    public void testIntoSameArray()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        CryptoServicesRegistrar.setNativeEnabled(false);

        // Java implementation of CCM mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CCMModeCipher ccmModeCipherEnc = new CCMBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        CryptoServicesRegistrar.setNativeEnabled(true);
        PacketCipher ccmPS = AESCCMPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(ccmPS.toString().contains("CCM-PS[Native]"));
            TestCase.assertTrue(ccmPS instanceof AESNativeCCMPacketCipher);
        }
        else
        {
            TestCase.assertTrue(ccmPS.toString().contains("CCM-PS[Java]"));
            TestCase.assertTrue(ccmPS instanceof AESCCMPacketCipher);
        }

        byte[] iv;

        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            for (int inLen : new int[]{7, 8, 9, 10, 11, 12, 13})
            {
                iv = new byte[inLen];
                secureRandom.nextBytes(iv);

                CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
                ccmModeCipherEnc.init(true, cp);

                for (int t = 0; t < 2048; t += 16)
                {
                    byte[] msg = new byte[t];
                    secureRandom.nextBytes(msg);

                    // We will slide around in the array also at odd addresses
                    byte[] workingArray = new byte[2 + msg.length + ccmModeCipherEnc.getOutputSize(msg.length)];


                    // Generate the expected cipher text from java CCM mode
                    byte[] expectedCText = new byte[ccmModeCipherEnc.getOutputSize(msg.length)];
                    ccmModeCipherEnc.reset();
                    ccmModeCipherEnc.processPacket(msg, 0, msg.length, expectedCText, 0);


                    for (int jiggle : new int[]{0, 1})
                    {
                        // Encryption
                        System.arraycopy(msg, 0, workingArray, jiggle, msg.length);
                        int len = ccmPS.processPacket(true, cp, workingArray, jiggle, msg.length, workingArray,
                            msg.length + jiggle);
                        TestCase.assertEquals(ccmPS.getOutputSize(true, cp, msg.length), len);

                        // Check cipher text
                        for (int j = 0; j < msg.length; j++)
                        {
                            if (expectedCText[j] != workingArray[j + msg.length + jiggle])
                            {
                                System.out.println(Hex.toHexString(workingArray));
                                System.out.println(Hex.toHexString(expectedCText));
                                System.out.println(jiggle);
                                fail("cipher text not same");
                            }
                        }


                        // Destroy plain text section
                        // as it should be written over with the correct plain text
                        Arrays.fill(workingArray, jiggle, msg.length + jiggle, (byte)1);


                        // Decryption
                        len = ccmPS.processPacket(false, cp, workingArray, msg.length + jiggle, len, workingArray,
                            jiggle);
                        TestCase.assertEquals(msg.length, len);

                        // Check cipher text
                        for (int j = 0; j < msg.length; j++)
                        {
                            if (msg[j] != workingArray[j + jiggle])
                            {
                                System.out.println(Hex.toHexString(workingArray));
                                System.out.println(Hex.toHexString(msg));
                                System.out.println(jiggle);

                                fail("plain text not same");
                            }

                        }

                    }

                }
            }

        }
    }

    public String getName()
    {
        return "CCM";
    }

    public static void main(
        String[] args)
        throws Exception
    {
        AESCCMPacketCipherTest test = new AESCCMPacketCipherTest();
        test.performTest();
        System.out.println("AESCCMPacketCipher Test pass");
    }
}
