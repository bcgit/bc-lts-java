package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeGCMPacketCipher;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Times;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class AESGCMPacketCipherTest
        extends TestCase
{

    public AESGCMPacketCipherTest()
    {

    }

    @Test
    public void testResetBehavior()
    throws Exception
    {

        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        AESGCMModePacketCipher gcm = AESGCMPacketCipher.newInstance();
        SecureRandom rnd = new SecureRandom();

        int[] ivLens = new int[]{12, 16};
        for (int i = 0; i != ivLens.length; i++)
        {
            int ivLen = ivLens[i];
            int[] kss = new int[]{16, 24, 32};
            for (int j = 0; j != kss.length; j++)
            {
                int ks = kss[j];
                byte[] key = new byte[ks];
                byte[] iv = new byte[ivLen];

                rnd.nextBytes(key);
                rnd.nextBytes(iv);

                byte[] msg = new byte[1024];
                rnd.nextBytes(msg);

                byte[] ct = new byte[gcm.getOutputSize(true, new ParametersWithIV(new KeyParameter(key), iv),
                        msg.length)];
                gcm.processPacket(true, new ParametersWithIV(new KeyParameter(key), iv), msg, 0, msg.length, ct, 0);

                //
                // Set up decrypt and do it before and after a reset.
                //
                byte[] outPreReset = new byte[msg.length];
                gcm.processPacket(false, new ParametersWithIV(new KeyParameter(key), iv), ct, 0, ct.length,
                        outPreReset, 0);

                byte[] outPostReset = new byte[msg.length];
                gcm.processPacket(false, new ParametersWithIV(new KeyParameter(key), iv), ct, 0, ct.length,
                        outPostReset, 0);

                TestCase.assertTrue("before / after reset decryptions not the same", Arrays.areEqual(outPreReset,
                        outPostReset));
                TestCase.assertTrue("decryption not same as message", Arrays.areEqual(msg, outPostReset));

            }

        }

    }

    @Test
    public void testExceptions()
    throws Exception
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        AESGCMModePacketCipher gcm = AESGCMPacketCipher.newInstance();
        try
        {
            gcm.getOutputSize(false, new KeyParameter(new byte[16]), 0);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals("invalid parameters passed to GCM"));
        }

        try
        {
            gcm.getOutputSize(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessages.LEN_NEGATIVE));
        }

        try
        {
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[28]), 128, new byte[16]),
                    new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.AES_KEY_LENGTH));
        }

        try
        {
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 127, new byte[16]),
                    new byte[16], 0, 16, new byte[32], 0);
            fail("invalid mac size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains("invalid mac size"));
        }

        try
        {
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), null, 0,
                    0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.INPUT_NULL));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[16], 0, 16, new byte[31], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.OUTPUT_LENGTH));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[16], -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[16], 0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.LEN_NEGATIVE));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(true, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[16], 0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[15], 0, 15, new byte[0], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.INPUT_SHORT));
        }

        try
        {
            ((Destroyable) gcm).destroy();
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]),
                    new byte[17], 0, 17, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessages.OUTPUT_LENGTH));
        }
    }

    @Test
    public void testOutputErase()
    throws Exception
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom rand = new SecureRandom();

        GCMBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
        byte[] key = new byte[16];
        byte[] iv = new byte[12];
        byte[] msg = new byte[17];

        rand.nextBytes(key);
        rand.nextBytes(iv);
        rand.nextBytes(msg);

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), iv);
        gcmBlockCipher.init(true, parameters);

        byte[] ct = new byte[gcmBlockCipher.getOutputSize(msg.length)];
        int l = gcmBlockCipher.processBytes(msg, 0, msg.length, ct, 0);
        gcmBlockCipher.doFinal(ct, l);

        // Vandalise cipher text
        ct[0] ^= 1;

        AESGCMModePacketCipher packetCipher = AESGCMPacketCipher.newInstance();
        byte[] pt = new byte[packetCipher.getOutputSize(false, parameters, ct.length) + 5];
        Arrays.fill(pt, (byte) 0x01);

        byte[] expected = Arrays.clone(pt);
        Arrays.fill(expected, 1, 1 + msg.length, (byte) 0x00);

        try
        {
            packetCipher.processPacket(false, parameters, ct, 0, ct.length, pt, 1);
            fail("tag should fail");
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(Arrays.areEqual(expected, pt));
        }

    }


    @Test
    public void testRandom()
    throws InvalidCipherTextException, PacketCipherException
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom srng = new SecureRandom();
        srng.setSeed(Times.nanoTime());

        for (int t = 0; t < 10000; t++)
        {
            execRandomTest(srng);
        }
    }


    private void execRandomTest(SecureRandom srng)
    throws PacketCipherException
    {
        int kLength = 16 + 8 * (Math.abs(srng.nextInt()) % 3);
        byte[] K = new byte[kLength];
        srng.nextBytes(K);

        int pLength = srng.nextInt() >>> 16;
        byte[] P = new byte[pLength];
        srng.nextBytes(P);

        int aLength = srng.nextInt() >>> 24;
        byte[] A = new byte[aLength];
        srng.nextBytes(A);

        int saLength = srng.nextInt() >>> 24;
        byte[] SA = new byte[saLength];
        srng.nextBytes(SA);

        int ivLength = 12 + srng.nextInt(4); //  1 + (srng.nextInt() >>> 24);
        byte[] IV = new byte[ivLength];
        srng.nextBytes(IV);

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        AESGCMModePacketCipher cipher = AESGCMPacketCipher.newInstance();
        byte[] C = new byte[cipher.getOutputSize(true, parameters, P.length)];

        int len = cipher.processPacket(true, parameters, P, 0, P.length, C, 0);

        if (C.length != len)
        {
            fail("encryption reported incorrect length in randomised test");
        }

        byte[] decP = new byte[cipher.getOutputSize(false, parameters, C.length)];
        len = cipher.processPacket(false, parameters, C, 0, C.length, decP, 0);

        if (!Arrays.areEqual(P, decP))
        {
            fail("incorrect decrypt in randomised test");
        }


        //
        // key reuse test
        //
        decP = new byte[cipher.getOutputSize(false, parameters, C.length)];
        len = cipher.processPacket(false, parameters, C, 0, C.length, decP, 0);
        if (!Arrays.areEqual(P, decP))
        {
            fail("incorrect decrypt in randomised test");
        }
    }

    @Test
    public void testOutputSize()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        byte[] K = new byte[16];
        byte[] A = null;
        byte[] IV = new byte[16];

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        AESGCMModePacketCipher cipher = AESGCMPacketCipher.newInstance();
        if (cipher.getOutputSize(true, parameters, 0) != 16)
        {
            fail("incorrect getOutputSize for initial 0 bytes encryption");
        }

        if (cipher.getOutputSize(false, parameters, 16) != 0)
        {
            fail("incorrect getOutputSize for initial MAC-size bytes decryption");
        }
    }


    @Test
    public void testAgreementForMultipleMessages()
    throws Exception
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        // Java implementation of GCM mode with the Java aes engine
        // Packet ciphers will be compared to this.
        GCMModeCipher gcmModeCipherEnc = new GCMBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        PacketCipher gcmPS = AESGCMPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(gcmPS.toString().contains("GCM-PS[Native]"));
            TestCase.assertTrue(gcmPS instanceof AESNativeGCMPacketCipher);
        }
        else
        {
            TestCase.assertTrue(gcmPS.toString().contains("GCM-PS[Java]"));
            TestCase.assertTrue(gcmPS instanceof AESGCMPacketCipher);
        }


        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            for (int ivLen : new int[]{12, 13, 14, 15, 16})
            {
                for (int t = 0; t < 1025; t += 1)
                {
                    for (int jitter = 0; jitter < 2; jitter++)
                    {
                        byte[] iv = new byte[ivLen];
                        secureRandom.nextBytes(iv);
                        CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);

                        gcmModeCipherEnc.reset();
                        byte[] msg = new byte[t + jitter];
                        secureRandom.nextBytes(msg);

                        gcmModeCipherEnc.init(true, cp);
                        // Generate expected message off the
                        int outLen = gcmModeCipherEnc.getOutputSize(msg.length - jitter);
                        byte[] expected = new byte[gcmModeCipherEnc.getOutputSize(msg.length - jitter) + jitter];

                        int resultLen = gcmModeCipherEnc.processBytes(msg, jitter, msg.length - jitter, expected,
                                jitter);
                        gcmModeCipherEnc.doFinal(expected, resultLen + jitter);

                        // Test encryption
                        int len = gcmPS.getOutputSize(true, cp, msg.length - jitter);
                        TestCase.assertEquals(outLen, len);
                        byte[] ctResult = new byte[len + jitter];

                        outLen = gcmPS.processPacket(true, cp, msg, jitter, msg.length - jitter, ctResult, jitter);

                        TestCase.assertEquals(ctResult.length - jitter, outLen);

                        // Test encrypted output same
                        TestCase.assertTrue(Arrays.areEqual(expected, ctResult));


                        // Test decryption

                        len = gcmPS.getOutputSize(false, cp, ctResult.length - jitter);
                        TestCase.assertEquals(msg.length - jitter, len);
                        byte[] ptResult = new byte[len + jitter];

                        outLen = gcmPS.processPacket(false, cp, ctResult, jitter, ctResult.length - jitter, ptResult,
                                jitter);
                        TestCase.assertEquals(msg.length - jitter, outLen);


                        byte[] expectedResult = Arrays.clone(msg);
                        for (int i = 0; i < jitter; i++)
                        {
                            expectedResult[i] = 0;
                        }

                        // Test encrypted output same
                        TestCase.assertTrue(Arrays.areEqual(expectedResult, ptResult));

                    }
                }
            }
        }
    }


    /**
     * Tests operation of packet cipher where input and output arrays are the same
     *
     * @throws Exception
     */
    @Test
    public void testIntoSameArray()
    throws Exception
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom secureRandom = new SecureRandom();

        // Java implementation of GCM mode with the Java aes engine
        // Packet ciphers will be compared to this.
        GCMModeCipher gcmModeCipherEnc = new GCMBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        PacketCipher gcmPS = AESGCMPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(gcmPS.toString().contains("GCM-PS[Native]"));
            TestCase.assertTrue(gcmPS instanceof AESNativeGCMPacketCipher);
        }
        else
        {
            TestCase.assertTrue(gcmPS.toString().contains("GCM-PS[Java]"));
            TestCase.assertTrue(gcmPS instanceof AESGCMPacketCipher);
        }

        byte[] iv;

        for (int ks : new int[]{16, 24, 32})
        {

            for (int inLen : new int[]{12, 13, 14, 15, 16})
            {
                byte[] key = new byte[ks];
                secureRandom.nextBytes(key);
                iv = new byte[inLen];

                for (int t = 0; t < 2049; t += 1)
                {
                    byte[] msg = new byte[t];
                    secureRandom.nextBytes(msg);
                    secureRandom.nextBytes(iv);


                    CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
                    gcmModeCipherEnc.init(true, cp);
                    // We will slide around in the array also at odd addresses
                    byte[] workingArray = new byte[2 + msg.length + gcmModeCipherEnc.getOutputSize(msg.length)];


                    // Generate the expected cipher text from java GCM mode
                    byte[] expectedCText = new byte[gcmModeCipherEnc.getOutputSize(msg.length)];
                    //gcmModeCipherEnc.reset();
                    int resultLen = gcmModeCipherEnc.processBytes(msg, 0, msg.length, expectedCText, 0);
                    gcmModeCipherEnc.doFinal(expectedCText, resultLen);

                    for (int jitter : new int[]{0, 1})
                    {
                        // Calling this disposes of a copy of the lastIV and lastKey circumvents nonce reuse detection!
                        // It is only done for expediency in this test and should not be done in the real use.
                        // Allow disposal to occur ONLY when finished with the instance.
                        ((Destroyable) gcmPS).destroy();
                        // Encryption
                        System.arraycopy(msg, 0, workingArray, jitter, msg.length);
                        int len = gcmPS.processPacket(true, cp, workingArray, jitter, msg.length, workingArray,
                                msg.length + jitter);
                        TestCase.assertEquals(gcmPS.getOutputSize(true, cp, msg.length), len);

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
                        len = gcmPS.processPacket(false, cp, workingArray, msg.length + jitter, len, workingArray,
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
    }

    boolean isNativeVariant()
    {
        String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
        if (variant == null || "java".equals(variant))
        {
            return false;
        }
        // May not be ported to native platform, so exercise java version only.
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM_PC);
    }


}
