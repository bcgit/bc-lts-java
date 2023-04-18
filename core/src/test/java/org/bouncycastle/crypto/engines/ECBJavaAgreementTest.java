package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Confirm that EBC implementations are in agreement with the Java version.
 */
public class ECBJavaAgreementTest extends TestCase
{
    private boolean hasAvx;

    @Before
    public void before()
    {

        CryptoServicesRegistrar.setNativeEnabled(true);
    }

    @After
    public void after()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    byte[] generateCT(byte[] message, byte[] key, boolean expectNative)
            throws Exception
    {
        MultiBlockCipher ecb = AESEngine.newInstance();
        ecb.init(true,new KeyParameter(key));

        if (expectNative) {
            TestCase.assertTrue(ecb.toString().contains("AES[Native]"));
        } else {
            TestCase.assertTrue(ecb.toString().contains("AES[Java]"));
        }
        
        byte[] out = new byte[message.length];
        ecb.processBlocks(message, 0, message.length / 16, out, 0);
        return out;
    }

    byte[] generatePT(byte[] ct, byte[] key, boolean expectNative)
            throws Exception
    {
        MultiBlockCipher ecb = AESEngine.newInstance();
        ecb.init(false,new KeyParameter(key));

        if (expectNative) {
            TestCase.assertTrue(ecb.toString().contains("AES[Native]"));
        } else {
            TestCase.assertTrue(ecb.toString().contains("AES[Java]"));
        }
        
        
        byte[] out = new byte[ct.length];
        ecb.processBlocks(ct, 0, ct.length / 16, out, 0);
        return out;

    }


    public void doTest(int keySize)
            throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] javaPT = new byte[16 * 4];
        secureRandom.nextBytes(javaPT);

        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);

        //
        // Generate expected result from Java API.
        //
        CryptoServicesRegistrar.setNativeEnabled(false);
        byte[] javaCT = generateCT(javaPT, key, false);
        TestCase.assertFalse(CryptoServicesRegistrar.getNativeServices().isEnabled());


        //
        // Turn on native
        //

        CryptoServicesRegistrar.setNativeEnabled(true);

        {

            byte[] ct = generateCT(javaPT, key, true);
            TestCase.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            byte[] pt = generatePT(javaCT, key, true);
            TestCase.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));
        }

    }

    @Test
    public void testEBCJavaAgreement_128()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(16);
    }

    @Test
    public void testEBCJavaAgreement_192()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(24);
    }

    @Test
    public void testEBCJavaAgreement_256()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(32);
    }


    /**
     * Test from one block to 64 blocks.
     * This wil exercise multi stages of block handling from single blocks to 16 block hunks.
     *
     * @throws Exception
     */
    @Test
    public void testECBSpreadNoPadding() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ecb"))
            {
                TestCase.fail("Skipping ECB Spread test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom rand = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {
            AESEngine javaEngineEnc = new AESEngine();
            AESNativeEngine nativeEngineEnc = new AESNativeEngine();

            AESEngine javaEngineDec = new AESEngine();
            AESNativeEngine nativeEngineDec = new AESNativeEngine();

            byte[] key = new byte[keySize];
            rand.nextBytes(key);
            javaEngineEnc.init(true, new KeyParameter(key));
            nativeEngineEnc.init(true, new KeyParameter(key));
            javaEngineDec.init(false, new KeyParameter(key));
            nativeEngineDec.init(false, new KeyParameter(key));


            for (int msgSize = 16; msgSize < 1024; msgSize += 16)
            {

                String pFix = String.format("Variant: %s, KeySize: %d, msgSize: %d ", CryptoServicesRegistrar.getNativeServices().getVariant(), keySize, msgSize);

                byte[] msg = new byte[msgSize];
                rand.nextBytes(msg);

                byte[] javaCT = new byte[msgSize];
                byte[] nativeCT = new byte[msgSize];

                Arrays.fill(javaCT, (byte) 1);
                Arrays.fill(nativeCT, (byte) 2);

                javaEngineEnc.processBlocks(msg, 0, msgSize / 16, javaCT, 0);
                nativeEngineEnc.processBlocks(msg, 0, msgSize / 16, nativeCT, 0);

                if (!Arrays.areEqual(nativeCT, javaCT))
                {
                    System.out.println(Hex.toHexString(nativeCT));
                    System.out.println(Hex.toHexString(javaCT));
                }

                Assert.assertTrue(pFix + "Cipher texts the same", Arrays.areEqual(nativeCT, javaCT));

                byte[] javaPt = new byte[msgSize];
                byte[] nativePt = new byte[msgSize];

                Arrays.fill(javaPt, (byte) 3);
                Arrays.fill(nativePt, (byte) 4);

                javaEngineDec.processBlocks(javaCT, 0, msgSize / 16, javaPt, 0);
                nativeEngineDec.processBlocks(nativeCT, 0, msgSize / 16, nativePt, 0);

                if (!Arrays.areEqual(nativePt, msg))
                {
                    System.out.println(Hex.toHexString(nativePt));
                    System.out.println(Hex.toHexString(msg));
                }
                Assert.assertTrue(pFix + "Native Pt same", Arrays.areEqual(nativePt, msg));
                Assert.assertTrue(pFix + "Java Pt same", Arrays.areEqual(javaPt, msg));

            }


        }


    }

}
