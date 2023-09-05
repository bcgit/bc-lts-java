package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class AESCBCPacketCipherTest
    extends TestCase
{
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(
        String[] args)
        throws Exception
    {
        AESCBCPacketCipherTest test= new AESCBCPacketCipherTest();
        test.performTest();
    }


    public void performTest()
        throws Exception
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
        runTests();
        CryptoServicesRegistrar.setNativeEnabled(false);
        runTests();
        System.out.println("AESCBCPacketCipherTest pass");
    }


    @Test
    public void test() throws Exception {
        // Entry point for junit
        performTest();
    }



    private void runTests()
        throws Exception
    {
        testExceptions();
        testCBC();
        testAgreement();
        testCBCJavaAgreement_128();
        testCBCJavaAgreement_192();
        testCBCJavaAgreement_256();

    }


    private void testCBC()
        throws Exception
    {


        List<Map<String, Object>> req = mapper.readValue(
            AESCBCPacketCipherTest.class.getResourceAsStream("CBC.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            AESCBCPacketCipherTest.class.getResourceAsStream("CBC.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        CBCBlockCipher javaCBC = new CBCBlockCipher(new AESEngine());
        AESCBCModePacketCipher packetCBC = AESPacketCipherEngine.createCBCPacketCipher();
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
                        // Native CBC.
                        //
                        List<Map<String, Object>> results = performMonteCarloCBCTest(packetCBC, reqGroup, reqTest);
                        //TestCase.assertEquals(expected.size(), results.size());
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
                        // Java CBC.
                        //
                        List<Map<String, Object>> results = performMonteCarloCBCTest(javaCBC, reqGroup, reqTest);
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

                    //nativeCBC.init(encryption, params);
                    javaCBC.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = packetCBC.processPacket(encryption, params, msg, 0, msg.length, nativeResult, 0);
                    int jrl = javaCBC.processBlocks(msg, 0, msg.length / javaCBC.getBlockSize(), javaResult, 0);
                    if (!Arrays.areEqual(nativeResult, expected))
                    {
                        packetCBC.processPacket(encryption, params, msg, 0, msg.length, nativeResult, 0);
                    }
                    TestCase.assertEquals("native output len matches java output len", nrl, jrl);
                    TestCase.assertTrue("native matches expected", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java matches expected", Arrays.areEqual(javaResult, expected));
                }
            }


        }
    }

    static List<Map<String, Object>> performMonteCarloCBCTest(CBCModeCipher driver, Map<String, Object> testGroup, Map<String, Object> test)
        throws Exception
    {
        List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();


        boolean encrypt = "encrypt".equals(testGroup.get("direction"));
        byte[] key = Hex.decode(test.get("key").toString());
        byte[] iv = Hex.decode(test.get("iv").toString());
        byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


        for (int i = 0; i <= 99; i++)
        {
            Map<String, Object> ares = new HashMap<String, Object>();
            results.add(ares);

            byte[] ctJ = null;
            byte[] ctJsub1 = null;

            ares.put("key", Arrays.clone(key));
            ares.put("iv", Arrays.clone(iv));

            if (encrypt)
            {
                ares.put("pt", Arrays.clone(input));

                for (int j = 0; j <= 999; j++)
                {
                    ctJsub1 = ctJ;
                    if (j == 0)
                    {

                        driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);
                        input = iv;
                    }
                    else
                    {
                        driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), ctJsub1));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);
                        input = ctJsub1;
                    }
                }

                iv = ctJ;
                input = ctJsub1;
                ares.put("ct", Arrays.clone(ctJ));
            }
            else
            {
                ares.put("ct", input);

                for (int j = 0; j <= 999; j++)
                {
                    ctJsub1 = ctJ;
                    if (j == 0)
                    {
                        driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);
                        // ctJ = driver.cbc(encrypt, key, iv, input);

                        byte[] tmp = iv;

                        iv = input;
                        input = tmp;
                    }
                    else
                    {

                        driver.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
                        ctJ = new byte[input.length];
                        driver.processBlocks(input, 0, input.length / 16, ctJ, 0);

                        // ctJ = driver.cbc(encrypt, key, iv, input);

                        iv = input;
                        input = ctJsub1;
                    }
                }

                iv = ctJ;
                input = ctJsub1;

                ares.put("pt", Arrays.clone(ctJ));
            }

            xorKey(key, ctJ, ctJsub1);


        }


        return results;
    }

    static List<Map<String, Object>> performMonteCarloCBCTest(AESCBCModePacketCipher driver, Map<String, Object> testGroup, Map<String, Object> test)
        throws Exception
    {
        List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();


        boolean encrypt = "encrypt".equals(testGroup.get("direction"));
        byte[] key = Hex.decode(test.get("key").toString());
        byte[] iv = Hex.decode(test.get("iv").toString());
        byte[] input = Hex.decode((test.containsKey("pt") ? test.get("pt") : test.get("ct")).toString());


        for (int i = 0; i <= 99; i++)
        {
            Map<String, Object> ares = new HashMap<String, Object>();
            results.add(ares);

            byte[] ctJ = null;
            byte[] ctJsub1 = null;

            ares.put("key", Arrays.clone(key));
            ares.put("iv", Arrays.clone(iv));

            if (encrypt)
            {
                ares.put("pt", Arrays.clone(input));

                for (int j = 0; j <= 999; j++)
                {
                    ctJsub1 = ctJ;
                    if (j == 0)
                    {
                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);
                        input = iv;
                    }
                    else
                    {
                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), ctJsub1), input, 0, input.length, ctJ, 0);
                        input = ctJsub1;
                    }
                }

                iv = ctJ;
                input = ctJsub1;
                ares.put("ct", Arrays.clone(ctJ));
            }
            else
            {
                ares.put("ct", input);

                for (int j = 0; j <= 999; j++)
                {
                    ctJsub1 = ctJ;
                    if (j == 0)
                    {
                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);

                        byte[] tmp = iv;

                        iv = input;
                        input = tmp;
                    }
                    else
                    {

                        ctJ = new byte[input.length];
                        driver.processPacket(encrypt, new ParametersWithIV(new KeyParameter(key), iv), input, 0, input.length, ctJ, 0);


                        iv = input;
                        input = ctJsub1;
                    }
                }

                iv = ctJ;
                input = ctJsub1;

                ares.put("pt", Arrays.clone(ctJ));
            }

            xorKey(key, ctJ, ctJsub1);


        }


        return results;
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

    private void testAgreement()
        throws InvalidCipherTextException, PacketCipherException
    {
        SecureRandom secureRandom = new SecureRandom();
        AESCBCModePacketCipher cbc2 = AESPacketCipherEngine.createCBCPacketCipher();
        int[] keybytes = {16, 24, 32};
        for (int i = 0; i < 3; ++i)
        {
            int keySize = keybytes[i];

            for (int t = 0; t < 4000; t++)
            {
                byte[] javaPT = new byte[(t + 1) << 4];
                secureRandom.nextBytes(javaPT);
                byte[] key = new byte[keySize];
                secureRandom.nextBytes(key);

                byte[] iv = new byte[16];
                secureRandom.nextBytes(iv);
                CBCBlockCipher cbc1 = new CBCBlockCipher(new AESEngine());
                ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
                cbc1.init(true, parameters);
                byte[] cbc1CT = new byte[javaPT.length];
                cbc1.processBlocks(javaPT, 0, javaPT.length / 16, cbc1CT, 0);

                byte[] cbc2CT = new byte[cbc2.getOutputSize(true, parameters, javaPT.length)];
                cbc2.processPacket(true, parameters, javaPT, 0, javaPT.length, cbc2CT, 0);

                if (!Arrays.areEqual(cbc1CT, cbc2CT))
                {
                    System.out.println(javaPT.length);
                    System.out.println(Hex.toHexString(cbc2CT));
                    System.out.println(Hex.toHexString(cbc1CT));
                    for (int j = 0; j < cbc2CT.length; j++)
                    {
                        if (cbc2CT[j] == cbc1CT[j])
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

                cbc1.init(true, parameters);
                byte[] cbc1PT = new byte[cbc1CT.length];
                cbc1.processBlocks(cbc1CT, 0, cbc1CT.length / 16, cbc1PT, 0);

                byte[] cbc2PT = new byte[cbc2.getOutputSize(true, parameters, cbc2CT.length)];
                cbc2.processPacket(true, parameters, cbc2CT, 0, cbc2CT.length, cbc2PT, 0);

                if (!Arrays.areEqual(cbc1PT, cbc2PT))
                {
                    System.out.println(javaPT.length);
                    System.out.println(Hex.toHexString(cbc1PT));
                    System.out.println(Hex.toHexString(cbc2PT));
                    for (int j = 0; j < cbc2CT.length; j++)
                    {
                        if (cbc2PT[j] == cbc1PT[j])
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

    @Override
    public String getName()
    {
        return "AESCBCPacketCipherTest";
    }

    byte[] generateCT(byte[] message, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CBCModeCipher cbc = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cbc.init(true, new ParametersWithIV(new KeyParameter(key), iv));


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cbc.toString().contains("CBC[Native](AES[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", cbc.toString().contains("CBC[Java](AES[Java]"));
        }

        byte[] out = new byte[message.length];

        cbc.processBlocks(message, 0, message.length / 16, out, 0);
        return out;

    }

    byte[] generatePT(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
        throws Exception
    {
        CBCModeCipher cbc = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cbc.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cbc.toString().contains("CBC[Native]"));
        }
        else
        {
            TestCase.assertTrue("Java implementation expected", cbc.toString().contains("CBC[Java]"));
        }

        byte[] pt = new byte[ct.length];

        cbc.processBlocks(ct, 0, ct.length / 16, pt, 0);
        return pt;


    }


    public void doTest(int keySize)
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] javaPT = new byte[16 * 4];
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
        TestCase.assertFalse(CryptoServicesRegistrar.getNativeServices().isEnabled());

        //
        // Turn on native
        //

        CryptoServicesRegistrar.setNativeEnabled(true);

        {
            //
            // Original AES-NI not AXV etc
            //
            byte[] ct = generateCT(javaPT, key, iv, true);
            TestCase.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            byte[] pt = generatePT(javaCT, key, iv, true);
            TestCase.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));
        }

    }

    @Test
    public void testCBCJavaAgreement_128()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CBC-PC"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc_pc"))
//            {
//                TestCase.fail("Skipping CBC_PC Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(16);
    }

    @Test
    public void testCBCJavaAgreement_192()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CBC-PC"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
//            {
//                TestCase.fail("Skipping CBC Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(24);
    }

    @Test
    public void testCBCJavaAgreement_256()
        throws Exception
    {
//        if (!TestUtil.hasNativeService("AES/CBC-PC"))
//        {
//            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
//            {
//                TestCase.fail("Skipping CBC Agreement Test: " + TestUtil.errorMsg());
//            }
//            return;
//        }
        doTest(32);
    }


    /**
     * Test from one block to 64 blocks.
     * This wil exercise multi stages of block handling from single blocks to 16 block hunks.
     *
     * @throws Exception
     */
    @Test
    public void testCBCSpreadNoPadding()
        throws Exception
    {

        SecureRandom rand = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {
            CBCBlockCipher javaEngineEnc = new CBCBlockCipher(new AESEngine());
            AESCBCModePacketCipher cbcPacketCipherJava = new AESCBCPacketCipher(); // AESPacketCipherEngine.createCBCPacketCipher();
            AESCBCModePacketCipher cbcPacketCipherNative = AESCBCPacketCipher.newInstance(); // May be java implementation if java is the module variant

            if (CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CBC_PC)) {
                TestCase.assertTrue(cbcPacketCipherNative.toString().contains("Native["));
            }


            CBCBlockCipher javaEngineDec = new CBCBlockCipher(new AESEngine());


            byte[] key = new byte[keySize];
            rand.nextBytes(key);

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            javaEngineEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            //cbcPacketCipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            javaEngineDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));
            //nativeEngineDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

            for (int msgSize = 16; msgSize < 1024; msgSize += 16)
            {

                String pFix = String.format("Variant: %s, KeySize: %d, msgSize: %d ", CryptoServicesRegistrar.getNativeServices().getVariant(), keySize, msgSize);


                byte[] msg = new byte[msgSize];
                rand.nextBytes(msg);

                byte[] javaCT = new byte[msgSize];
                byte[] nativeCT = new byte[msgSize];

                Arrays.fill(javaCT, (byte)1);
                Arrays.fill(nativeCT, (byte)2);

                for (int j = 0; j < msgSize / 16; j++)
                {
                    javaEngineEnc.processBlock(msg, j * 16, javaCT, j * 16);
                }

                cbcPacketCipherJava.processPacket(true, new ParametersWithIV(new KeyParameter(key), iv), msg, 0, msgSize, nativeCT, 0);

                TestCase.assertTrue(pFix + "Cipher texts the same", Arrays.areEqual(nativeCT, javaCT));


                byte[] javaPt = new byte[msgSize];
                byte[] nativePt = new byte[msgSize];

                Arrays.fill(javaPt, (byte)3);
                Arrays.fill(nativePt, (byte)4);

                for (int j = 0; j < javaCT.length / 16; j++)
                {
                    javaEngineDec.processBlock(javaCT, j * 16, javaPt, j * 16);
                }

                cbcPacketCipherJava.processPacket(true, new ParametersWithIV(new KeyParameter(key), iv), nativeCT, 0, msgSize, nativePt, 0);

                if (!Arrays.areEqual(nativePt, msg))
                {
                    System.out.println(Hex.toHexString(msg));
                    System.out.println(Hex.toHexString(nativePt));
                }

                TestCase.assertTrue(pFix + "Native Pt same", Arrays.areEqual(nativePt, msg));
                TestCase.assertTrue(pFix + "Java Pt same", Arrays.areEqual(javaPt, msg));

            }


        }


    }

    public void testExceptions()
    {
        AESCBCModePacketCipher cbc = AESPacketCipherEngine.createCBCPacketCipher();

        try
        {
            cbc.getOutputSize(false, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]), -1);
            fail("negative value for getOutputSize");
        }
        catch (IllegalArgumentException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().equals(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[18]), new byte[16]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.AES_KEY_LENGTH));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]), new byte[16], 0, 16, new byte[32], 0);
            fail("invalid key size for processPacket");
        }
        catch (PacketCipherException e)
        {
            // expected
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.CBC_IV_LENGTH));
        }


        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), null, 0, 0, new byte[16], 0);
            fail("input was null for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_NULL));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[15], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[15], 0, 15, new byte[16], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.BLOCK_CIPHER_16_INPUT_LENGTH_INVALID));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], -1, 16, new byte[32], 0);
            fail("offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, -1, new byte[32], 0);
            fail("len is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.LEN_NEGATIVE));
        }

        try
        {
            cbc.processPacket(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[16], -1);
            fail("output offset is negative for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_OFFSET_NEGATIVE));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 32, new byte[32], 0);
            fail("input buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.INPUT_LENGTH));
        }

        try
        {
            cbc.processPacket(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]), new byte[16], 0, 16, new byte[0], 0);
            fail("output buffer too small for processPacket");
        }
        catch (PacketCipherException e)
        {
            TestCase.assertTrue("wrong message", e.getMessage().contains(ExceptionMessage.OUTPUT_LENGTH));
        }
    }
}
