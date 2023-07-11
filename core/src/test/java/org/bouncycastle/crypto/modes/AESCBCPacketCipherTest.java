package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.NativeBlockCipherProvider;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

public class AESCBCPacketCipherTest
    extends SimpleTest
{
    private static ObjectMapper mapper = new ObjectMapper();

    public static void main(
        String[] args)
    {
        runTest(new AESCBCPacketCipherTest());
    }

    @Override
    public void performTest()
        throws Exception
    {
        testCBC();
        System.out.println("AESCBCPacketCipherTest pass");
    }

    @Test
    public void testCBC()
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
        AESCBCPacketCipher packetCBC = AESCBCPacketCipher.newInstance();
        for (int gi = 0; gi < reqGroups.size(); gi++)
        {
            Map<String, Object> reqGroup = reqGroups.get(gi);
            Map<String, Object> rspGroup = rspGroups.get(gi);

            List<Map<String, Object>> reqTests = (List<Map<String, Object>>)reqGroup.get("tests");
            List<Map<String, Object>> rspTests = (List<Map<String, Object>>)rspGroup.get("tests");

            String testType = (String)reqGroup.get("testType");
            if (gi == 39)
            {
                System.out.println("break");
            }

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
                                if (!Arrays.areEqual(Hex.decode(left.get(key).toString()), (byte[])right.get(key)))
                                {
                                    System.out.println("break");
                                }
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
                    if(!Arrays.areEqual(nativeResult, expected)){
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

    static List<Map<String, Object>> performMonteCarloCBCTest(AESCBCPacketCipher driver, Map<String, Object> testGroup, Map<String, Object> test)
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
        AESCCMPacketCipher ccm2 = AESCCMPacketCipher.newInstance();
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

    @Override
    public String getName()
    {
        return null;
    }


}
