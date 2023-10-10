package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.NativeBlockCipherProvider;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESNativeCFBPacketCipher;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class AESCFBPacketCipherTest
        extends TestCase
{

    public AESCFBPacketCipherTest() {

    }



    @Test
    public void testExceptions()
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        AESCFBModePacketCipher cfb = AESPacketCipherEngine.createCFBPacketCipher();

        try
        {
            cfb.getOutputSize(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16],
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
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0,
                    new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16],
                    0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16]
                    , 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }

    @Test
    public void testAgreementForMultipleMessages()
            throws Exception
    {
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom rand = new SecureRandom();
        AESCFBModePacketCipher cfbPkt =  AESCFBPacketCipher.createCFBPacketCipher();
        isCorrectTypeForVariant(cfbPkt);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            rand.nextBytes(key);

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            for (int msgSize = 0; msgSize < 1025; msgSize++)
            {

                for (int jitter = 0; jitter < 2; jitter++)
                {

                    byte[] msg = new byte[msgSize + jitter];
                    rand.nextBytes(msg);

                    CFBBlockCipher cfbReference = new CFBBlockCipher(new AESEngine(), 128);

                    cfbReference.init(true, parameters);
                    byte[] cfbExpectedCt = new byte[msg.length];
                    cfbReference.processBytes(msg, jitter, msg.length - jitter, cfbExpectedCt, jitter);

                    byte[] cfbPCCt = new byte[cfbPkt.getOutputSize(true, parameters, msg.length - jitter) + jitter];
                    cfbPkt.processPacket(true, parameters, msg, jitter, msg.length - jitter, cfbPCCt, jitter);
                    TestCase.assertTrue(Arrays.areEqual(cfbExpectedCt, cfbPCCt));

                    // Set up expected value for decryption
                    byte[] cfbExpectedPt = new byte[msg.length];
                    cfbReference.init(false, parameters);
                    cfbReference.processBytes(cfbExpectedCt, jitter, msg.length - jitter, cfbExpectedPt, jitter);

                    byte[] cfbPCPt = new byte[cfbPkt.getOutputSize(true, parameters, msg.length - jitter) + jitter];
                    cfbPkt.processPacket(false, parameters, cfbPCCt, jitter, msg.length - jitter, cfbPCPt, jitter);

                    TestCase.assertTrue(Arrays.areEqual(cfbExpectedPt, cfbPCPt));


                    // If there is jitter then the operations will have taken data at an offset
                    // When msg is created the whole array is filled with random data.
                    // Finally, when plain texts are generated they will be generated into empty arrays
                    // and will have leading zero values.
                    byte[] expectedResult = Arrays.clone(msg);
                    for (int i = 0; i < jitter; i++)
                    {
                        expectedResult[i] = 0;
                    }
                    TestCase.assertTrue(Arrays.areEqual(cfbExpectedPt, expectedResult)); // sanity

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
        if (TestUtil.skipPS()) {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        SecureRandom secureRandom = new SecureRandom();


        // Java implementation of CFB mode with the Java aes engine
        // Packet ciphers will be compared to this.
        CFBModeCipher cfbModeCipherEnc = new CFBBlockCipher(new AESEngine(), 128);

        //
        //  Implementation of packet cipher, may be native or java depending on variant used in testing
        //
        PacketCipher cfbPS = AESCFBPacketCipher.newInstance();

        isCorrectTypeForVariant(cfbPS);


        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            CipherParameters cp = new ParametersWithIV(new KeyParameter(key), iv);
            cfbModeCipherEnc.init(true, cp);

            for (int t = 0; t < 2048; t++)
            {
                byte[] msg = new byte[t];
                secureRandom.nextBytes(msg);

                // We will slide around in the array also at odd addresses
                byte[] workingArray = new byte[2 + msg.length * 2];


                // Generate the expected cipher text from java CFB mode
                byte[] expectedCText = new byte[msg.length];
                cfbModeCipherEnc.reset();
                cfbModeCipherEnc.processBytes(msg, 0, msg.length, expectedCText, 0);


                for (int jitter : new int[]{0, 1})
                {
                    // Encryption
                    System.arraycopy(msg, 0, workingArray, jitter, msg.length);
                    int len = cfbPS.processPacket(true, cp, workingArray, jitter, msg.length, workingArray,
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
                    len = cfbPS.processPacket(false, cp, workingArray, msg.length + jitter, msg.length, workingArray,
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
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CFB_PC);
    }

    private void isCorrectTypeForVariant(Object o)
    {
        //
        // Verify we are getting is what we expect.
        //
        if (isNativeVariant())
        {
            TestCase.assertTrue(o.toString().contains("CFB-PS[Native]"));
            TestCase.assertTrue(o instanceof AESNativeCFBPacketCipher);
        }
        else
        {
            TestCase.assertTrue(o.toString().contains("CFB-PS[Java]"));
            TestCase.assertTrue(o instanceof AESCFBPacketCipher);
        }
    }

}
