package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCBCPacketCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Rule;
import org.junit.Test;

public class AESCBCPacketCipherTest
        extends TestCase
{
    public AESCBCPacketCipherTest()
    {

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


    @Test
    public void testAgreementForMultipleMessages() throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        CryptoServicesRegistrar.setNativeEnabled(false);

        // Java implementation of CBC mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CBCModeCipher cbcModeCipherEnc = new CBCBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        CryptoServicesRegistrar.setNativeEnabled(true);
        PacketCipher cbcPS = AESCBCPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(cbcPS.toString().contains("CBC-PS[Native]"));
            TestCase.assertTrue(cbcPS instanceof AESNativeCBCPacketCipher);
        }
        else
        {
            TestCase.assertTrue(cbcPS.toString().contains("CBC-PS[Java]"));
            TestCase.assertTrue(cbcPS instanceof AESCBCPacketCipher);
        }

        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
            cbcModeCipherEnc.init(true, cp);


            for (int t = 0; t < 8192; t += 16)
            {
                cbcModeCipherEnc.reset();
                byte[] msg = new byte[t];
                secureRandom.nextBytes(msg);

                // Generate expected message off the
                byte[] expected = new byte[msg.length];
                cbcModeCipherEnc.processBlocks(msg, 0, msg.length / 16, expected, 0);


                // Test encryption
                int len = cbcPS.getOutputSize(true, cp, msg.length);
                TestCase.assertEquals(msg.length, len);
                byte[] ctResult = new byte[len];

                int outLen = cbcPS.processPacket(true, cp, msg, 0, msg.length, ctResult, 0);
                TestCase.assertEquals(msg.length, outLen);

                // Test encrypted output same
                TestCase.assertTrue(Arrays.areEqual(expected, ctResult));


                // Test decryption

                len = cbcPS.getOutputSize(false, cp, ctResult.length);
                TestCase.assertEquals(msg.length, len);
                byte[] ptResult = new byte[len];

                outLen = cbcPS.processPacket(false, cp, ctResult, 0, ctResult.length, ptResult, 0);
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
    @Test
    public void testIntoSameArray() throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        // Java implementation of CBC mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CBCModeCipher cbcModeCipherEnc = new CBCBlockCipher(new AESEngine());

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        PacketCipher cbcPS = AESCBCPacketCipher.newInstance();


        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(cbcPS.toString().contains("CBC-PS[Native]"));
            TestCase.assertTrue(cbcPS instanceof AESNativeCBCPacketCipher);
        }
        else
        {
            TestCase.assertTrue(cbcPS.toString().contains("CBC-PS[Java]"));
            TestCase.assertTrue(cbcPS instanceof AESCBCPacketCipher);
        }

        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
            cbcModeCipherEnc.init(true, cp);


            for (int t = 16; t < 2048; t += 16)
            {
                byte[] msg = new byte[t];
                secureRandom.nextBytes(msg);

                // We will slide around in the array also at odd addresses
                byte[] workingArray = new byte[2 + msg.length * 2];


                // Generate the expected cipher text from java CBC mode
                byte[] expectedCText = new byte[msg.length];
                cbcModeCipherEnc.reset();
                cbcModeCipherEnc.processBlocks(msg, 0, msg.length / 16, expectedCText, 0);


                for (int jiggle : new int[]{0, 1})
                {
                    // Encryption
                    System.arraycopy(msg, 0, workingArray, jiggle, msg.length);
                    int len = cbcPS.processPacket(true, cp, workingArray, jiggle, msg.length, workingArray,
                            msg.length + jiggle);
                    TestCase.assertEquals(msg.length, len);

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
                    Arrays.fill(workingArray, jiggle, msg.length + jiggle, (byte) 1);


                    // Decryption
                    len = cbcPS.processPacket(false, cp, workingArray, msg.length + jiggle, msg.length, workingArray,
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


    @Test
    public void testExceptions()
    {
        AESCBCModePacketCipher cbc = AESPacketCipherEngine.createCBCPacketCipher();

        try
        {
            cbc.getOutputSize(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16],
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
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]), new byte[16],
                    0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.CBC_IV_LENGTH));
        }


        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0,
                    new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[15]
                    , 0, 15, new byte[16], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message",
                    e.getMessage().contains(ExceptionMessage.BLOCK_CIPHER_16_INPUT_LENGTH_INVALID));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[16], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }
}
