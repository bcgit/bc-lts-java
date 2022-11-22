package org.bouncycastle.test.engines;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.NativeBlockCipherProvider;
import org.bouncycastle.crypto.NativeService;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class NativeACVPTest
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
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/ECB.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/ECB.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        MultiBlockCipher nativeEngine = AESEngine.newInstance();
        if (!(nativeEngine instanceof NativeBlockCipherProvider))
        {
            throw new IllegalStateException("did not get instance of ");
        }


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


    @Test
    public void testGCM()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/GCM"))
        {
            System.out.println("Skipping GCM native ACVP vector test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }


        List<Map<String, Object>> req = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/GCM.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/GCM.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        GCMModeCipher nativeGCM = ((NativeBlockCipherProvider)AESEngine.newInstance()).createGCM();
        if (!(nativeGCM instanceof NativeService))
        {
            throw new IllegalStateException("expected native GCM got " + nativeGCM.getClass().getName());
        }

        GCMModeCipher javaGCM = new GCMBlockCipher(new AESEngine());

        for (int gi = 0; gi < reqGroups.size(); gi++)
        {
            Map<String, Object> reqGroup = reqGroups.get(gi);
            Map<String, Object> rspGroup = rspGroups.get(gi);

            List<Map<String, Object>> reqTests = (List<Map<String, Object>>)reqGroup.get("tests");
            List<Map<String, Object>> rspTests = (List<Map<String, Object>>)rspGroup.get("tests");


            for (int ti = 0; ti < reqTests.size(); ti++)
            {


                Map<String, Object> reqTest = reqTests.get(ti);
                Map<String, Object> rspTest = rspTests.get(ti);


                int tagLen = Integer.parseInt(reqGroup.get("tagLen").toString());
                boolean encryption = "encrypt".equals(reqGroup.get("direction"));
                AEADParameters params = new AEADParameters(
                    new KeyParameter(Hex.decode(reqTest.get("key").toString())),
                    tagLen,
                    Hex.decode(reqTest.get("iv").toString()));


                if (encryption)
                {

                    byte[] msg = Hex.decode(reqTest.get("pt").toString());
                    byte[] aad = Hex.decode(reqTest.get("aad").toString());

                    byte[] expected = Hex.decode(rspTest.get("ct").toString() + rspTest.get("tag").toString());

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    nativeGCM.init(true, params);
                    javaGCM.init(true, params);
                    nativeGCM.processAADBytes(aad, 0, aad.length);
                    javaGCM.processAADBytes(aad, 0, aad.length);

                    int nrl = nativeGCM.processBytes(msg, 0, msg.length, nativeResult, 0);
                    int jrl = javaGCM.processBytes(msg, 0, msg.length, javaResult, 0);
                    nativeGCM.doFinal(nativeResult, nrl);
                    javaGCM.doFinal(javaResult, jrl);

                    TestCase.assertTrue("native GCM", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java GCM", Arrays.areEqual(javaResult, expected));

                }
                else
                {
                    byte[] msg = Hex.decode(reqTest.get("ct").toString() + reqTest.get("tag").toString());
                    byte[] aad = Hex.decode(reqTest.get("aad").toString());


                    nativeGCM.init(false, params);
                    javaGCM.init(false, params);


                    byte[] nativeResult = new byte[nativeGCM.getOutputSize(msg.length)];
                    byte[] javaResult = new byte[javaGCM.getOutputSize(msg.length)];


                    nativeGCM.processAADBytes(aad, 0, aad.length);
                    javaGCM.processAADBytes(aad, 0, aad.length);

                    int nrl = nativeGCM.processBytes(msg, 0, msg.length, nativeResult, 0);
                    int jrl = javaGCM.processBytes(msg, 0, msg.length, javaResult, 0);

                    boolean nPass;
                    try
                    {
                        nativeGCM.doFinal(nativeResult, nrl);
                        nPass = true;
                    }
                    catch (Exception ex)
                    {
                        Assert.assertEquals("mac check in GCM failed", ex.getMessage());
                        nPass = false;
                    }

                    boolean jPass;
                    try
                    {
                        javaGCM.doFinal(javaResult, jrl);
                        jPass = true;
                    }
                    catch (Exception ex)
                    {
                        Assert.assertEquals("mac check in GCM failed", ex.getMessage());
                        jPass = false;
                    }

                    if (!rspTest.containsKey("testPassed") && !rspTest.containsKey("pt"))
                    {

                        //
                        // Sanity.
                        //

                        throw new IllegalStateException("result did not contain testPassed and pt");
                    }


                    if (rspTest.containsKey("testPassed"))
                    {
                        boolean testPassed = Boolean.valueOf(rspTest.get("testPassed").toString());
                        TestCase.assertEquals(testPassed, jPass);
                        TestCase.assertEquals(testPassed, nPass);
                    }
                    if (rspTest.containsKey("pt"))
                    {
                        byte[] expected = Hex.decode(rspTest.get("pt").toString());
                        TestCase.assertTrue("native GCM", Arrays.areEqual(nativeResult, expected));
                        TestCase.assertTrue("java GCM", Arrays.areEqual(javaResult, expected));
                    }


                }


            }


        }
    }


    @Test
    public void testCFB()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CFB"))
        {
            System.out.println("Skipping CFB native ACVP vector test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        List<Map<String, Object>> req = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CFB128.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CFB128.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        CFBModeCipher nativeCFB = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
        if (!(nativeCFB instanceof NativeService))
        {
            throw new IllegalStateException("expected native CFB got " + nativeCFB.getClass().getName());
        }

        CFBBlockCipher javaCBC = new CFBBlockCipher(new AESEngine(), 128);

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
                        List<Map<String, Object>> results = performMonteCarloTest(nativeCFB, reqGroup, reqTest, "CFB128");
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
                        List<Map<String, Object>> results = performMonteCarloTest(javaCBC, reqGroup, reqTest, "CFB128");
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
                    javaCBC.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = nativeCFB.processBlocks(msg, 0, msg.length / nativeCFB.getBlockSize(), nativeResult, 0);
                    int jrl = javaCBC.processBlocks(msg, 0, msg.length / javaCBC.getBlockSize(), javaResult, 0);

                    TestCase.assertEquals("native output len matches java output len", nrl, jrl);
                    TestCase.assertTrue("native matches expected", Arrays.areEqual(nativeResult, expected));
                    TestCase.assertTrue("java matches expected", Arrays.areEqual(javaResult, expected));
                }
            }


        }
    }

    @Test
    public void testCFBStreamCipher()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CFB"))
        {
            System.out.println("Skipping CFB native ACVP vector test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        List<Map<String, Object>> req = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CFB128.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CFB128.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        CFBModeCipher nativeCFB = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
        if (!(nativeCFB instanceof NativeService))
        {
            throw new IllegalStateException("expected native CFB got " + nativeCFB.getClass().getName());
        }

        CFBModeCipher nativeCFBByte = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCFB(128);
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


    @Test
    public void testCBC()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasFeature("AES/CBC"))
        {
            System.out.println("Skipping CBC native ACVP vector test: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }


        List<Map<String, Object>> req = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CBC.req.json"),
            List.class);

        List<Map<String, Object>> rsp = mapper.readValue(
            NativeACVPTest.class.getResourceAsStream("/crypto/modes/crypto/modes/CBC.rsp.json"),
            List.class);

        List<Map<String, Object>> reqGroups = ((List<Map<String, Object>>)(req.get(1)).get("testGroups"));

        List<Map<String, Object>> rspGroups = ((List<Map<String, Object>>)(rsp.get(1)).get("testGroups"));


        CBCModeCipher nativeCBC = ((NativeBlockCipherProvider)AESEngine.newInstance()).createCBC();
        if (!(nativeCBC instanceof NativeService))
        {
            throw new IllegalStateException("expected native CFB got " + nativeCBC.getClass().getName());
        }

        CBCBlockCipher javaCBC = new CBCBlockCipher(new AESEngine());

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
                        List<Map<String, Object>> results = performMonteCarloCBCTest(nativeCBC, reqGroup, reqTest);
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

                    nativeCBC.init(encryption, params);
                    javaCBC.init(encryption, params);

                    byte[] nativeResult = new byte[expected.length];
                    byte[] javaResult = new byte[expected.length];

                    int nrl = nativeCBC.processBlocks(msg, 0, msg.length / nativeCBC.getBlockSize(), nativeResult, 0);
                    int jrl = javaCBC.processBlocks(msg, 0, msg.length / javaCBC.getBlockSize(), javaResult, 0);

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
