package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessage;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.NativeBlockCipherProvider;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.AESPacketCipherEngine;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
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
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(
        String[] args)
        throws Exception
    {
        AESCFBPacketCipherTest test= new AESCFBPacketCipherTest();
        test.performTest();
    }

    @Override
    public String getName()
    {
        return null;
    }

    @Test
    public void performTest()
        throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        Tests();
        CryptoServicesRegistrar.setNativeEnabled(false);
        Tests();
        System.out.println("AESCFBPacketCipherTest pass");
    }

    public void Tests()
        throws Exception
    {
        testExceptions();
        testCFB();
//        testCFBSpread();
        //testCFBStreamCipher();
//        testAgreement();
        testCFBJavaAgreement_128();
        testCFBJavaAgreement_192();
        testCFBJavaAgreement_256();
    }

    public void testExceptions()
    {
        AESCFBModePacketCipher cfb = AESPacketCipherEngine.createCFBPacketCipher();

        try
        {
            cfb.getOutputSize(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[15], 0, 15, new byte[16], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_DECRYPTION_INPUT_LENGTH_INVALID));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cfb.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[32], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            cfb.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }


    public void testCFB()
        throws Exception
    {
//        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_CFB))
//        {
//            System.out.println("Skipping CFB native ACVP vector test: " + TestUtil.errorMsg());
//            return;
//        }

        List<Map<String, Object>> req = mapper.readValue(
            AESCFBPacketCipherTest.class.getResourceAsStream("CFB128.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            AESCFBPacketCipherTest.class.getResourceAsStream("CFB128.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


//        CFBModeCipher nativeCFB = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
//
//        if (!(nativeCFB.toString().contains("CFB[Native]")))
//        {
//            throw new IllegalStateException("expected native CFB got " + nativeCFB.getClass().getName());
//        }
        AESCFBModePacketCipher packetCFB = AESPacketCipherEngine.createCFBPacketCipher();

        CFBBlockCipher javaCFB = new CFBBlockCipher(new AESEngine(), 128);

        for (int gi = 0; gi < reqGroups.size(); gi++)
        {
            Map<String, Object> reqGroup = reqGroups.get(gi);
            Map<String, Object> rspGroup = rspGroups.get(gi);

            List<Map<String, Object>> reqTests = (List<Map<String, Object>>)reqGroup.get("tests");
            List<Map<String, Object>> rspTests = (List<Map<String, Object>>)rspGroup.get("tests");

            String testType = (String)reqGroup.get("testType");


            for (int ti = 0; ti < reqTests.size(); ti++)
            {


                Map<String, Object> reqTest = reqTests.get(ti);
                Map<String, Object> rspTest = rspTests.get(ti);


                if ("MCT".equals(testType))
                {

                    List<Map<String, Object>> expected = (List<Map<String, Object>>)rspTest.get("resultsArray");
                    {
                        //
                        // Native CFB.
                        //
                        List<Map<String, Object>> results = performMonteCarloTest(packetCFB, reqGroup, reqTest, "CFB128");
                        TestCase.assertEquals(expected.size(), results.size());
                        for (int t = 0; t < expected.size(); t++)
                        {
                            Map<String, Object> left = expected.get(t);
                            Map<String, Object> right = results.get(t);

                            for (String key : right.keySet())
                            {
                                TestCase.assertTrue("native " + t + " - " + key, Arrays.areEqual(Hex.decode(left.get(key).toString()), (byte[])right.get(key)));
                            }
                        }
                    }


                    {
                        //
                        // Java CFB.
                        //
                        List<Map<String, Object>> results = performMonteCarloTest(javaCFB, reqGroup, reqTest, "CFB128");
                        TestCase.assertEquals(expected.size(), results.size());
                        for (int t = 0; t < expected.size(); t++)
                        {
                            Map<String, Object> left = expected.get(t);
                            Map<String, Object> right = results.get(t);

                            for (String key : right.keySet())
                            {
                                TestCase.assertTrue("java " + t + " - " + key, Arrays.areEqual(Hex.decode(left.get(key).toString()), (byte[])right.get(key)));
                            }
                        }
                    }


                }
                else
                {

                    boolean encryption = "encrypt".equals(reqGroup.get("direction"));
                    ParametersWithIV params = new ParametersWithIV(new KeyParameter(Hex.decode(reqTest.get("key").toString())), Hex.decode(reqTest.get("iv").toString()));
                    byte[] msg = Hex.decode((reqTest.containsKey("pt") ? reqTest.get("pt") : reqTest.get("ct")).toString());
                    byte[] expected = Hex.decode((rspTest.containsKey("pt") ? rspTest.get("pt") : rspTest.get("ct")).toString());

//                    nativeCFB.init(encryption, params);
                    javaCFB.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = packetCFB.processPacket(encryption, params, msg, 0, msg.length, nativeResult, 0);
                    int jrl = javaCFB.processBlocks(msg, 0, msg.length / javaCFB.getBlockSize(), javaResult, 0);
//                    if (!Arrays.areEqual(nativeResult, expected))
//                    {
//                        nrl = packetCFB.processPacket(encryption, params, msg, 0, msg.length, nativeResult, 0);
//                    }
                    TestCase.assertEquals("native output len matches java output len", nrl, jrl);
                    TestCase.assertTrue("native matches expected", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java matches expected", Arrays.areEqual(javaResult, expected));
//                    System.out.println("Pass");
                }
            }


        }
    }

    static List<Map<String, Object>> performMonteCarloTest(AESCFBModePacketCipher driver, Map<String, Object> testGroup, Map<String, Object> test, String mode)
        throws Exception
    {
        List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();


        if (!mode.equals("ECB"))
        {

            boolean encrypt = "encrypt".equals(testGroup.get("direction"));
            byte[] key = Hex.decode(test.get("key").toString());
            byte[] iv = Hex.decode(test.get("iv").toString());
            byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


            // Cipher c = Cipher.getInstance("AES/" + mode + "/NoPadding", "BCFIPS");


            for (int i = 0; i <= 99; i++)
            {
                Map<String, Object> ares = new HashMap<String, Object>();
                results.add(ares);

                byte[] ctJ = null;
                byte[] ctJsub1 = null;

                ares.put("key", Arrays.clone(key));
                ares.put("iv", iv);

                if (mode.equals("OFB"))
                {
                    byte[] prevInput = null;

                    if (encrypt)
                    {
                        ares.put("pt", input);
                    }
                    else
                    {
                        ares.put("ct", input);
                    }

                    // responseWriter.outputField(config.isEncrypt() ? "PLAINTEXT" : "CIPHERTEXT", input);

                    //  int cipherMode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;

                        if (j == 0)
                        {
//                            c.init(cipherMode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//
//                            ctJ = c.doFinal(input);

                            //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                            ctJ = new byte[input.length];
                            driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);


                            prevInput = input;
                            input = iv;
                        }
                        else
                        {
                            byte[] nextIv = xor(ctJsub1, prevInput);
//                            c.init(cipherMode, new SecretKeySpec(key, "AES"), new IvParameterSpec(nextIv));
//
//                            ctJ = c.doFinal(input);

                            //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), nextIv));
                            ctJ = new byte[input.length];
                            driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);


                            prevInput = input;
                            input = ctJsub1;
                        }
                    }

                    if (encrypt)
                    {
                        ares.put("ct", ctJ);
                    }
                    else
                    {
                        ares.put("pt", ctJ);
                    }


                    xorKey(key, ctJ, ctJsub1);
                    iv = ctJ;
                    input = ctJsub1;
                }
                else
                {
                    if (encrypt)
                    {
                        ares.put("pt", input);


                        for (int j = 0; j <= 999; j++)
                        {
                            ctJsub1 = ctJ;
                            if (j == 0)
                            {
//                                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//
//                                    ctJ = c.doFinal(input);

                                //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);


                                input = iv;
                            }
                            else
                            {
//                                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(ctJsub1));
//
//                                    ctJ = c.doFinal(input);


                                //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), ctJsub1));
                                ctJ = new byte[input.length];
                                driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), ctJsub1), input, 0, input.length, ctJ, 0);


                                input = ctJsub1;
                            }
                        }

                        iv = ctJ;
                        input = ctJsub1;
                        ares.put("ct", ctJ);
                        //}
                    }
                    else
                    {
                        ares.put("ct", input);


                        for (int j = 0; j <= 999; j++)
                        {
                            ctJsub1 = ctJ;
                            if (j == 0)
                            {
                                //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);

                                // ctJ = c.doFinal(input);

                                byte[] tmp = iv;

                                iv = input;
                                input = tmp;
                            }
                            else
                            {
                                //driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);


                                // ctJ = c.doFinal(input);

                                iv = input;
                                input = ctJsub1;
                            }
                        }

                        iv = ctJ;
                        input = ctJsub1;

                        ares.put("pt", ctJ);
                        // }
                    }

                    xorKey(key, ctJ, ctJsub1);
                }


            }
        }
        else
        {

            boolean encrypt = "encrypt".equals(testGroup.get("direction"));
            byte[] key = Hex.decode(test.get("key").toString());

            byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


            for (int i = 0; i <= 99; i++)
            {
                Map<String, Object> ares = new HashMap<String, Object>();
                results.add(ares);

                byte[] ctJ = null;
                byte[] ctJsub1 = null;

                ares.put("key", Arrays.clone(key));

                if (encrypt)
                {
                    ares.put("pt", input);

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;
                        //driver.init(encrypt, new KeyParameter(key));
                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new KeyParameter(key), input, 0, input.length, ctJ, 0);
                        input = ctJ;
                    }
                    ares.put("ct", ctJ);
                }
                else
                {
                    ares.put("ct", input);

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;
                        //driver.init(encrypt, new KeyParameter(key));
                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new KeyParameter(key), input, 0, input.length, ctJ, 0);

                        // ctJ = driver.ecb(encrypt, key, input);

                        input = ctJ;
                    }

                    ares.put("pt", ctJ);
                }

                xorKey(key, ctJ, ctJsub1);
                input = ctJ;

            }
        }


        return results;
    }

    static List<Map<String, Object>> performMonteCarloTest(MultiBlockCipher driver, Map<String, Object> testGroup, Map<String, Object> test, String mode)
        throws Exception
    {
        List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();


        if (!mode.equals("ECB"))
        {

            boolean encrypt = "encrypt".equals(testGroup.get("direction"));
            byte[] key = Hex.decode(test.get("key").toString());
            byte[] iv = Hex.decode(test.get("iv").toString());
            byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


            // Cipher c = Cipher.getInstance("AES/" + mode + "/NoPadding", "BCFIPS");


            for (int i = 0; i <= 99; i++)
            {
                Map<String, Object> ares = new HashMap<String, Object>();
                results.add(ares);

                byte[] ctJ = null;
                byte[] ctJsub1 = null;

                ares.put("key", Arrays.clone(key));
                ares.put("iv", iv);

                if (mode.equals("OFB"))
                {
                    byte[] prevInput = null;

                    if (encrypt)
                    {
                        ares.put("pt", input);
                    }
                    else
                    {
                        ares.put("ct", input);
                    }

                    // responseWriter.outputField(config.isEncrypt() ? "PLAINTEXT" : "CIPHERTEXT", input);

                    //  int cipherMode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;

                        if (j == 0)
                        {
//                            c.init(cipherMode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//
//                            ctJ = c.doFinal(input);

                            driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                            ctJ = new byte[input.length];
                            driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                            prevInput = input;
                            input = iv;
                        }
                        else
                        {
                            byte[] nextIv = xor(ctJsub1, prevInput);
//                            c.init(cipherMode, new SecretKeySpec(key, "AES"), new IvParameterSpec(nextIv));
//
//                            ctJ = c.doFinal(input);

                            driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), nextIv));
                            ctJ = new byte[input.length];
                            driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                            prevInput = input;
                            input = ctJsub1;
                        }
                    }

                    if (encrypt)
                    {
                        ares.put("ct", ctJ);
                    }
                    else
                    {
                        ares.put("pt", ctJ);
                    }


                    xorKey(key, ctJ, ctJsub1);
                    iv = ctJ;
                    input = ctJsub1;
                }
                else
                {
                    if (encrypt)
                    {
                        ares.put("pt", input);


                        for (int j = 0; j <= 999; j++)
                        {
                            ctJsub1 = ctJ;
                            if (j == 0)
                            {
//                                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//
//                                    ctJ = c.doFinal(input);

                                driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                                input = iv;
                            }
                            else
                            {
//                                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(ctJsub1));
//
//                                    ctJ = c.doFinal(input);


                                driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), ctJsub1));
                                ctJ = new byte[input.length];
                                driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                                input = ctJsub1;
                            }
                        }

                        iv = ctJ;
                        input = ctJsub1;
                        ares.put("ct", ctJ);
                        //}
                    }
                    else
                    {
                        ares.put("ct", input);


                        for (int j = 0; j <= 999; j++)
                        {
                            ctJsub1 = ctJ;
                            if (j == 0)
                            {
                                //c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));


                                driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processBlocks(input, 0, input.length / 16, ctJ, 0);

                                // ctJ = c.doFinal(input);

                                byte[] tmp = iv;

                                iv = input;
                                input = tmp;
                            }
                            else
                            {
                                //  c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));


                                driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                                ctJ = new byte[input.length];
                                driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                                // ctJ = c.doFinal(input);

                                iv = input;
                                input = ctJsub1;
                            }
                        }

                        iv = ctJ;
                        input = ctJsub1;

                        ares.put("pt", ctJ);
                        // }
                    }

                    xorKey(key, ctJ, ctJsub1);
                }


            }
        }
        else
        {

            boolean encrypt = "encrypt".equals(testGroup.get("direction"));
            byte[] key = Hex.decode(test.get("key").toString());

            byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


            for (int i = 0; i <= 99; i++)
            {
                Map<String, Object> ares = new HashMap<String, Object>();
                results.add(ares);

                byte[] ctJ = null;
                byte[] ctJsub1 = null;

                ares.put("key", Arrays.clone(key));

                if (encrypt)
                {
                    ares.put("pt", input);

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;


                        driver.init(encrypt, new KeyParameter(key));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);


                        //ctJ = driver.ecb(encrypt, key, input);

                        input = ctJ;
                    }

                    ares.put("ct", ctJ);
                }
                else
                {
                    ares.put("ct", input);

                    for (int j = 0; j <= 999; j++)
                    {
                        ctJsub1 = ctJ;


                        driver.init(encrypt, new KeyParameter(key));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);

                        // ctJ = driver.ecb(encrypt, key, input);

                        input = ctJ;
                    }

                    ares.put("pt", ctJ);
                }

                xorKey(key, ctJ, ctJsub1);
                input = ctJ;

            }
        }


        return results;
    }

    public void testCFBStreamCipher()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_CFB))
        {
            System.out.println("Skipping CFB native ACVP vector test: " + TestUtil.errorMsg());
            return;
        }

        List<Map<String, Object>> req = mapper.readValue(
            AESCFBPacketCipherTest.class.getResourceAsStream("CFB128.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            AESCFBPacketCipherTest.class.getResourceAsStream("CFB128.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));

        CryptoServicesRegistrar.setNativeEnabled(true);
        CFBModeCipher nativeCFB = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
        if (!(nativeCFB.toString().contains("CFB[Native]")))
        {
            throw new IllegalStateException("expected native CFB got " + nativeCFB.getClass().getName());
        }

        CFBModeCipher nativeCFBByte = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
        CryptoServicesRegistrar.setNativeEnabled(false);
        CFBBlockCipher javaCFB = new CFBBlockCipher(new AESEngine(), 128);

        for (int gi = 0; gi < reqGroups.size(); gi++)
        {
            Map<String, Object> reqGroup = reqGroups.get(gi);
            Map<String, Object> rspGroup = rspGroups.get(gi);

            List<Map<String, Object>> reqTests = (List<Map<String, Object>>)reqGroup.get("tests");
            List<Map<String, Object>> rspTests = (List<Map<String, Object>>)rspGroup.get("tests");

            String testType = (String)reqGroup.get("testType");


            for (int ti = 0; ti < reqTests.size(); ti++)
            {


                Map<String, Object> reqTest = reqTests.get(ti);
                Map<String, Object> rspTest = rspTests.get(ti);


                if ("MCT".equals(testType))
                {

                    List<Map<String, Object>> expected = (List<Map<String, Object>>)rspTest.get("resultsArray");
                    {
                        //
                        // Native CFB.
                        //
                        List<Map<String, Object>> results = performMonteCarloTest(nativeCFBByte, reqGroup, reqTest, "CFB128");
                        TestCase.assertEquals(expected.size(), results.size());
                        for (int t = 0; t < expected.size(); t++)
                        {
                            Map<String, Object> left = expected.get(t);
                            Map<String, Object> right = results.get(t);

                            for (String key : right.keySet())
                            {
                                TestCase.assertTrue("native " + t + " - " + key, Arrays.areEqual(Hex.decode(left.get(key).toString()), (byte[])right.get(key)));
                            }
                        }
                    }


                    {
                        //
                        // Java CFB.
                        //
                        List<Map<String, Object>> results = performMonteCarloTest(javaCFB, reqGroup, reqTest, "CFB128");
                        TestCase.assertEquals(expected.size(), results.size());
                        for (int t = 0; t < expected.size(); t++)
                        {
                            Map<String, Object> left = expected.get(t);
                            Map<String, Object> right = results.get(t);

                            for (String key : right.keySet())
                            {
                                TestCase.assertTrue("java " + t + " - " + key, Arrays.areEqual(Hex.decode(left.get(key).toString()), (byte[])right.get(key)));
                            }
                        }
                    }


                }
                else
                {

                    boolean encryption = "encrypt".equals(reqGroup.get("direction"));
                    ParametersWithIV params = new ParametersWithIV(new KeyParameter(Hex.decode(reqTest.get("key").toString())), Hex.decode(reqTest.get("iv").toString()));
                    byte[] msg = Hex.decode((reqTest.containsKey("pt") ? reqTest.get("pt") : reqTest.get("ct")).toString());
                    byte[] expected = Hex.decode((rspTest.containsKey("pt") ? rspTest.get("pt") : rspTest.get("ct")).toString());

                    nativeCFB.init(encryption, params);
                    nativeCFBByte.init(encryption, params);
                    javaCFB.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = nativeCFB.processBytes(msg, 0, msg.length, nativeResult, 0);
                    int jrl = javaCFB.processBytes(msg, 0, msg.length, javaResult, 0);

                    TestCase.assertEquals("native output len matches java output len", nrl, jrl);
                    TestCase.assertTrue("native matches expected", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java matches expected", Arrays.areEqual(javaResult, expected));

                    //
                    // Test byte by byte interface works.
                    //

                    int exptPtr = 0;
                    for (int t = 0; t < msg.length; t++)
                    {
                        byte z = nativeCFBByte.returnByte(msg[t]);
                        TestCase.assertEquals(z, nativeResult[exptPtr++]);
                    }


                }
            }


        }
    }

    private static void xorKey(byte[] key, byte[] ctJ, byte[] ctJsub1)
    {
        if (key.length == 16)
        {
            for (int k = 0; k != 16; k++)
            {
                key[k] ^= ctJ[k];
            }
        }
        else if (key.length == 24)
        {
            for (int k = 0; k != 8; k++)
            {
                key[k] ^= ctJsub1[(ctJsub1.length - 8) + k];
            }
            for (int k = 0; k != 16; k++)
            {
                key[8 + k] ^= ctJ[k];
            }
        }
        else if (key.length == 32)
        {
            for (int k = 0; k != 16; k++)
            {
                key[k] ^= ctJsub1[k];
            }
            for (int k = 0; k != 16; k++)
            {
                key[16 + k] ^= ctJ[k];
            }
        }
    }

    private static byte[] xor(byte[] a, byte[] b)
    {
        byte[] n = new byte[a.length];

        for (int i = 0; i != a.length; i++)
        {
            n[i] = (byte)(a[i] ^ b[i]);
        }

        return n;
    }

    byte[] generateCTByteOff(byte[] message, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(true, new ParametersWithIV(new KeyParameter(key), iv));


//        if (expectNative)
//        {
//            Assert.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
//        }
//        else
//        {
//            Assert.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
//        }

        byte[] out = new byte[message.length];
        out[0] = cfb.returnByte(message[0]);

        cfb.processBytes(message, 1, message.length - 1, out, 1);
        return out;

    }

    byte[] generateCT(byte[] message, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(true, new ParametersWithIV(new KeyParameter(key), iv));


//        if (expectNative)
//        {
//            Assert.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
//        }
//        else
//        {
//            Assert.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
//        }

        byte[] out = new byte[message.length];

        cfb.processBytes(message, 0, message.length, out, 0);
        return out;

    }

    byte[] generatePT(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(false, new ParametersWithIV(new KeyParameter(key), iv));


//        if (expectNative)
//        {
//            Assert.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
//        }
//        else
//        {
//            Assert.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
//        }

        byte[] out = new byte[ct.length];

        cfb.processBytes(ct, 0, ct.length, out, 0);
        return out;


    }


    byte[] generatePTByteOff(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(false, new ParametersWithIV(new KeyParameter(key), iv));


//        if (expectNative)
//        {
//            Assert.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
//        }
//        else
//        {
//            Assert.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
//        }

        byte[] out = new byte[ct.length];
        out[0] = cfb.returnByte(ct[0]);

        cfb.processBytes(ct, 1, ct.length - 1, out, 1);
        return out;

    }


    public void doTest(int keySize)
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] javaPT = new byte[16 * 17];
        secureRandom.nextBytes(javaPT);

        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);

        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        //
        // Generate expected result from Java API.
        //
        CryptoServicesRegistrar.setNativeEnabled(false);
        byte[] javaCT = generateCT(javaPT, key, iv, false);
        Assert.assertFalse(CryptoServicesRegistrar.getNativeServices().isEnabled());

        //
        // Turn on native
        //

        CryptoServicesRegistrar.setNativeEnabled(true);

        {
            //
            // Original AES-NI not AXV etc
            //
            byte[] ct = generateCT(javaPT, key, iv, true);

            if (!Arrays.areEqual(ct, javaCT))
            {
                System.out.println(Hex.toHexString(javaCT));
                System.out.println(Hex.toHexString(ct));
            }

            Assert.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            byte[] pt = generatePT(javaCT, key, iv, true);

            Assert.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));

            ct = generateCTByteOff(javaPT, key, iv, true);
            Assert.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            pt = generatePTByteOff(javaCT, key, iv, true);

            if (!Arrays.areEqual(pt, javaPT))
            {
                System.out.println(Hex.toHexString(javaPT));
                System.out.println(Hex.toHexString(pt));
            }

            Assert.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));

        }

    }



    public void testCFBJavaAgreement_128()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CFB"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
//            {
//                Assert.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(16);
    }


    public void testCFBJavaAgreement_192()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CFB"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
//            {
//                Assert.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(24);
    }


    public void testCFBJavaAgreement_256()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CFB"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
//            {
//                Assert.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(32);
    }


    /**
     * Test every byte length from 0 to 1025 bytes as a stream cipher.
     *
     * @throws Exception
     */

    public void testCFBSpreadBbB()
        throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cfb"))
            {
                Assert.fail("Skipping CFB spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();
        AESCFBModePacketCipher packetCFB = AESPacketCipherEngine.createCFBPacketCipher();
        for (int keySize : new int[]{16, 24, 32})
        {

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            byte[] key = new byte[keySize];
            rand.nextBytes(key);

//            AESNativeCFB nativeEnc = new AESNativeCFB();
//            nativeEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
//
//
//            AESNativeCFB nativeDec = new AESNativeCFB();
//            nativeDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

            CFBBlockCipher javaEnc = new CFBBlockCipher(new AESEngine(), 128);
            javaEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));

            CFBBlockCipher javaDec = new CFBBlockCipher(new AESEngine(), 128);
            javaDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] msg = new byte[2049];
            rand.nextBytes(msg);

            for (int lim = 0; lim < msg.length; lim++)
            {
                byte[] nCt = new byte[lim];
                byte[] nPt = new byte[lim];

                byte[] jCt = new byte[lim];
                byte[] jPt = new byte[lim];

                rand.nextBytes(nCt);
                rand.nextBytes(nPt);
                rand.nextBytes(jCt);
                rand.nextBytes(jPt);

                for (int t = 0; t < lim; t++)
                {
                    //nCt[t] = nativeEnc.returnByte(msg[t]);
                    jCt[t] = javaEnc.returnByte(msg[t]);
                }
                packetCFB.processPacket(true, new ParametersWithIV(new KeyParameter(key), iv), msg, 0, lim, nCt, 0);

                for (int t = 0; t < lim; t++)
                {
                    //nPt[t] = nativeDec.returnByte(nCt[t]);
                    jPt[t] = javaDec.returnByte(jCt[t]);
                }
                packetCFB.processPacket(false, new ParametersWithIV(new KeyParameter(key), iv), nCt, 0, lim, nPt, 0);
                Assert.assertTrue("Key Size: " + keySize + " javaCT = nativeCt", Arrays.areEqual(jCt, nCt));
                if (!Arrays.areEqual(jPt, nPt))
                {
                    System.out.println(Hex.toHexString(jPt));
                    System.out.println(Hex.toHexString(nPt));
                }
                Assert.assertTrue("Key Size: " + keySize + " javaPt = nativePt", Arrays.areEqual(jPt, nPt));
                Assert.assertTrue("Key Size: " + keySize + " message = javaPt", Arrays.areEqual(jPt, Arrays.copyOfRange(msg, 0, lim)));
            }
        }
    }


}
