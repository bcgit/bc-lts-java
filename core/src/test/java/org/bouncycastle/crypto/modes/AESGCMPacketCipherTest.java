package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeGCMPacketCipher;
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

    public AESGCMPacketCipherTest() {

    }

    @Test
    public void testResetBehavior()
            throws Exception
    {
        AESGCMModePacketCipher gcm = AESPacketCipherEngine.createGCMPacketCipher();
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
            throws DestroyFailedException
    {
        AESGCMModePacketCipher gcm = AESPacketCipherEngine.createGCMPacketCipher();
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
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains("Invalid value for MAC size"));
        }

        try
        {
            gcm.processPacket(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), null, 0,
                    0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_SHORT));
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
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }

    @Test
    public void testOutputErase()
    {
        String testVector[] = {
                "Test Case 3",
                "feffe9928665731c6d6a8f9467308308",
                "d9313225f88406e5a55909c5aff5269a"
                        + "86a7a9531534f7da2e4c303d8a318a72"
                        + "1c3c0c95956809532fcf0e2449a6b525"
                        + "b16aedf5aa0de657ba637b391aafd255",
                "",
                "cafebabefacedbaddecaf888",
                "42831ec2217774244b7221b784d0d49c"
                        + "e3aa212f2c02a4e035c17e2329aca12e"
                        + "21d514b25466931c7d8f6a5aac84aa05"
                        + "1ba30b396a0aac973d58e091473f5985",
                "4d5c2af327cd64a62cf35abd2ba6fab4",
        };

        byte[] K = Hex.decode(testVector[1]);
        byte[] P = Hex.decode(testVector[2]);
        byte[] A = Hex.decode(testVector[3]);
        byte[] IV = Hex.decode(testVector[4]);
        byte[] C = Hex.decode(testVector[5]);
        byte[] T = Hex.decode(testVector[6]);
        AESGCMModePacketCipher GCMgcm = AESPacketCipherEngine.createGCMPacketCipher();
        byte[] C3new = Arrays.clone(C);
        C3new[0]++;
        KeyParameter keyParam = (K == null) ? null : new KeyParameter(K);
        AEADParameters parameters = new AEADParameters(keyParam, 64, IV, A);
        int len = GCMgcm.getOutputSize(false, parameters, C3new.length + T.length) + C3new.length + T.length;
        byte[] dec = new byte[len];
        System.arraycopy(C3new, 0, dec, 0, C3new.length);
        byte[] origin = Arrays.clone(dec);

        try
        {
            GCMgcm.processPacket(false, parameters, dec, 0, C3new.length + T.length, dec, C3new.length + T.length);
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


    @Test
    public void testRandom()
            throws InvalidCipherTextException, PacketCipherException
    {
        SecureRandom srng = new SecureRandom();
        srng.setSeed(Times.nanoTime());

        for (int t=0; t<10000; t++)
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
        AESGCMModePacketCipher cipher = AESPacketCipherEngine.createGCMPacketCipher();
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
        byte[] K = new byte[16];
        byte[] A = null;
        byte[] IV = new byte[16];

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        AESGCMModePacketCipher cipher = AESPacketCipherEngine.createGCMPacketCipher();
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
                        byte[] msg = new byte[t+jitter];
                        secureRandom.nextBytes(msg);

                        gcmModeCipherEnc.init(true, cp);
                        // Generate expected message off the
                        int outLen = gcmModeCipherEnc.getOutputSize(msg.length-jitter);
                        byte[] expected = new byte[gcmModeCipherEnc.getOutputSize(msg.length-jitter)+jitter];

                        int resultLen = gcmModeCipherEnc.processBytes(msg, jitter, msg.length-jitter, expected, jitter);
                        gcmModeCipherEnc.doFinal(expected, resultLen+jitter);

                        // Test encryption
                        int len = gcmPS.getOutputSize(true, cp, msg.length-jitter);
                        TestCase.assertEquals(outLen, len);
                        byte[] ctResult = new byte[len+jitter];

                        outLen = gcmPS.processPacket(true, cp, msg, jitter, msg.length-jitter, ctResult, jitter);
                        TestCase.assertEquals(ctResult.length-jitter, outLen);

                        // Test encrypted output same
                        TestCase.assertTrue(Arrays.areEqual(expected, ctResult));


                        // Test decryption

                        len = gcmPS.getOutputSize(false, cp, ctResult.length-jitter);
                        TestCase.assertEquals(msg.length-jitter, len);
                        byte[] ptResult = new byte[len+jitter];

                        outLen = gcmPS.processPacket(false, cp, ctResult, jitter, ctResult.length-jitter, ptResult, jitter);
                        TestCase.assertEquals(msg.length-jitter, outLen);


                        byte[] expectedResult = Arrays.clone(msg);
                        for (int i =0; i<jitter; i++) {
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
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            for (int inLen : new int[]{12, 13, 14, 15, 16})
            {
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
        return true;
    }


}
