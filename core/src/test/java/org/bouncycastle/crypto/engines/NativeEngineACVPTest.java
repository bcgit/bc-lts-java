package org.bouncycastle.crypto.engines;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class NativeEngineACVPTest
{

    private static ObjectMapper mapper = new ObjectMapper();


    @Test
    public void testECB()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/ECB"))
        {
            System.out.println("Skipping ECB native ACVP vector test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }


        List<Map<String, Object>> req = mapper.readValue(
            NativeEngineACVPTest.class.getResourceAsStream("/org/bouncycastle/crypto/modes/ECB.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeEngineACVPTest.class.getResourceAsStream("/org/bouncycastle/crypto/modes/ECB.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        AESNativeEngine nativeEngine = new AESNativeEngine();
        AESEngine javaEngine = new AESEngine();

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
                        List<Map<String, Object>> results = performMonteCarloTest(nativeEngine, reqGroup, reqTest, "ECB");
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
                        // Java CBC.
                        //
                        List<Map<String, Object>> results = performMonteCarloTest(javaEngine, reqGroup, reqTest, "ECB");
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
                    KeyParameter params = new KeyParameter(Hex.decode(reqTest.get("key").toString()));
                    byte[] msg = Hex.decode((reqTest.containsKey("pt") ? reqTest.get("pt") : reqTest.get("ct")).toString());
                    byte[] expected = Hex.decode((encryption ? rspTest.get("ct") : rspTest.get("pt")).toString());

                    nativeEngine.init(encryption, params);
                    javaEngine.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = nativeEngine.processBlocks(msg, 0, msg.length / nativeEngine.getBlockSize(), nativeResult, 0);
                    int jrl = javaEngine.processBlocks(msg, 0, msg.length / javaEngine.getBlockSize(), javaResult, 0);

                    TestCase.assertEquals("native output len matches java output len", nrl, jrl);
                    TestCase.assertTrue("native matches expected", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java matches expected", Arrays.areEqual(javaResult, expected));
                }
            }


        }
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
}
