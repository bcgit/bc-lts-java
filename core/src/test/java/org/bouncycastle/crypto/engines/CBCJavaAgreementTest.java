package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Confirm that CBC implementations are in agreement with the Java version.
 */
public class CBCJavaAgreementTest extends TestCase
{

    @Before
    public void setup()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    @After
    public void after()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);
    }


    byte[] generateCT(byte[] message, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {


        CBCModeCipher cbc = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cbc.init(true,new ParametersWithIV(new KeyParameter(key),iv));


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cbc.toString().contains("CBC[Native](AES[Native]"));
        } else
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
        cbc.init(false,new ParametersWithIV(new KeyParameter(key),iv));

        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cbc.toString().contains("CBC[Native]"));
        } else
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
        if (!TestUtil.hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(16);
    }

    @Test
    public void testCBCJavaAgreement_192()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(24);
    }

    @Test
    public void testCBCJavaAgreement_256()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Agreement Test: " + TestUtil.errorMsg());
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
    public void testCBCSpreadNoPadding() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CBC"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CBC Spread Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {
            CBCBlockCipher javaEngineEnc = new CBCBlockCipher(new AESEngine());
            AESNativeCBC nativeEngineEnc = new AESNativeCBC();

            CBCBlockCipher javaEngineDec = new CBCBlockCipher(new AESEngine());
            AESNativeCBC nativeEngineDec = new AESNativeCBC();

            byte[] key = new byte[keySize];
            rand.nextBytes(key);

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            javaEngineEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            nativeEngineEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            javaEngineDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));
            nativeEngineDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

            for (int msgSize = 16; msgSize < 1024; msgSize += 16)
            {

                String pFix = String.format("Variant: %s, KeySize: %d, msgSize: %d ", CryptoServicesRegistrar.getNativeServices().getVariant(), keySize, msgSize);


                byte[] msg = new byte[msgSize];
                rand.nextBytes(msg);

                byte[] javaCT = new byte[msgSize];
                byte[] nativeCT = new byte[msgSize];

                Arrays.fill(javaCT, (byte) 1);
                Arrays.fill(nativeCT, (byte) 2);

                for (int j = 0; j < msgSize / 16; j++)
                {
                    javaEngineEnc.processBlock(msg, j * 16, javaCT, j * 16);
                }

                nativeEngineEnc.processBlocks(msg, 0, msgSize / 16, nativeCT, 0);

                TestCase.assertTrue(pFix + "Cipher texts the same", Arrays.areEqual(nativeCT, javaCT));


                byte[] javaPt = new byte[msgSize];
                byte[] nativePt = new byte[msgSize];

                Arrays.fill(javaPt, (byte) 3);
                Arrays.fill(nativePt, (byte) 4);

                for (int j = 0; j < javaCT.length / 16; j++)
                {
                    javaEngineDec.processBlock(javaCT, j * 16, javaPt, j * 16);
                }

                nativeEngineDec.processBlocks(nativeCT, 0, msgSize / 16, nativePt, 0);

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


}
