package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CFBModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Confirm that CFB implementations are in agreement with the Java version.
 */
public class CFBJavaAgreementTest extends TestCase
{


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


    byte[] generateCTByteOff(byte[] message, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(true, new ParametersWithIV(new KeyParameter(key), iv));


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
        } else
        {
            TestCase.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
        }

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


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
        } else
        {
            TestCase.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
        }

        byte[] out = new byte[message.length];

        cfb.processBytes(message, 0, message.length, out, 0);
        return out;

    }

    byte[] generatePT(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(false, new ParametersWithIV(new KeyParameter(key), iv));


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
        } else
        {
            TestCase.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
        }

        byte[] out = new byte[ct.length];

        cfb.processBytes(ct, 0, ct.length, out, 0);
        return out;


    }


    byte[] generatePTByteOff(byte[] ct, byte[] key, byte[] iv, boolean expectNative)
            throws Exception
    {
        CFBModeCipher cfb = CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
        cfb.init(false, new ParametersWithIV(new KeyParameter(key), iv));


        if (expectNative)
        {
            TestCase.assertTrue("Native implementation expected", cfb.toString().contains("CFB[Native](AES[Native]"));
        } else
        {
            TestCase.assertTrue("Java implementation expected", cfb.toString().contains("CFB[Java](AES[Java]"));
        }

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

            if (!Arrays.areEqual(ct, javaCT))
            {
                System.out.println(Hex.toHexString(javaCT));
                System.out.println(Hex.toHexString(ct));
            }

            TestCase.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            byte[] pt = generatePT(javaCT, key, iv, true);

            TestCase.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));

            ct = generateCTByteOff(javaPT, key, iv, true);
            TestCase.assertTrue(keySize + " AES-NI CT did not match", Arrays.areEqual(ct, javaCT));

            pt = generatePTByteOff(javaCT, key, iv, true);

            if (!Arrays.areEqual(pt, javaPT))
            {
                System.out.println(Hex.toHexString(javaPT));
                System.out.println(Hex.toHexString(pt));
            }

            TestCase.assertTrue(keySize + " AES-NI PT did not match", Arrays.areEqual(pt, javaPT));

        }

    }


    void doTestByteByByte(int keySize) throws Exception
    {

        int l = 2049;

        byte[] key = new byte[keySize];
        byte[] iv = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        random.nextBytes(iv);

        AESNativeCFB engine = new AESNativeCFB();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] msg = new byte[l];
        random.nextBytes(msg);

        byte[] ct = new byte[l];

        for (int t = 0; t < msg.length; t++)
        {
            ct[t] = engine.returnByte(msg[t]);
        }


        engine.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] pt = new byte[l];

        for (int t = 0; t < ct.length; t++)
        {
            pt[t] = engine.returnByte(ct[t]);
        }

        TestCase.assertTrue("did not round trip byte by byte", Arrays.areEqual(pt, msg));

    }

    @Test
    public void testCFBJavaAgreement_128()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(16);
        doTestByteByByte(16);
    }

    @Test
    public void testCFBJavaAgreement_192()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(24);
        doTestByteByByte(24);
    }

    @Test
    public void testCFBJavaAgreement_256()
            throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }
        doTest(32);
        doTestByteByByte(32);
    }


    /**
     * Randomly test different combinations of single byte and random byet array lenhth
     * inputs, compare ongoing output to java version.
     */
    @Test
    public void testStreamingMonte() throws Exception
    {

        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB streaming monte Test: " + TestUtil.errorMsg());
            }
            return;
        }

        byte[] seed = new byte[10];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(seed);

        // Copy seed value from error report to this and uncomment to
        // reproduce the same series of operations with the same values.

        // seed = Hex.decode("174343ccc52983b997f8");

        StreamingFixedSecureRandom ssr = new StreamingFixedSecureRandom(seed);


        byte[] key = new byte[16];
        byte[] iv = new byte[16];

        ssr.nextBytes(key);
        ssr.nextBytes(iv);

        ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);

        AESNativeCFB nativeEnc = new AESNativeCFB();
        nativeEnc.init(true, params);

        AESNativeCFB nativeDec = new AESNativeCFB();
        nativeDec.init(false, params);

        CFBBlockCipher javaEnc = new CFBBlockCipher(new AESEngine(), 128);
        javaEnc.init(true, params);

        CFBBlockCipher javaDec = new CFBBlockCipher(new AESEngine(), 128);
        javaDec.init(false, params);


        for (int t = 0; t < 500000; t++)
        {

            int dice = ssr.nextInt(6);
            if (dice < 3)
            {
                byte b = (byte) ssr.nextInt();
                byte nc = nativeEnc.returnByte(b);
                byte jc = javaEnc.returnByte(b);

                TestCase.assertEquals(Hex.toHexString(seed) + " ct equal jc", nc, jc);

                byte np = nativeDec.returnByte(nc);
                byte jp = javaDec.returnByte(jc);

                TestCase.assertEquals(Hex.toHexString(seed) + " pt equal jp", np, jp);

            } else
            {
                byte[] msg = new byte[ssr.nextInt(256)];
                byte[] nc = new byte[msg.length];
                byte[] jc = new byte[msg.length];

                byte[] np = new byte[msg.length];
                byte[] jp = new byte[msg.length];

                ssr.nextBytes(nc);
                ssr.nextBytes(jc);
                ssr.nextBytes(np);
                ssr.nextBytes(jp);

                nativeEnc.processBytes(msg, 0, msg.length, nc, 0);
                javaEnc.processBytes(msg, 0, msg.length, jc, 0);

                TestCase.assertTrue(Hex.toHexString(seed) + " Java CT = Native Ct", Arrays.areEqual(jc, nc));


                nativeDec.processBytes(nc, 0, nc.length, np, 0);
                javaDec.processBytes(jc, 0, jc.length, jp, 0);

                TestCase.assertTrue(Hex.toHexString(seed) + " Java PT = Native Pt", Arrays.areEqual(jp, np));

            }
        }
    }


    /**
     * Test every byte length from 0 to 1025 bytes as a stream cipher.
     *
     * @throws Exception
     */
    @Test
    public void testCFBSpreadBbB() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            byte[] key = new byte[keySize];
            rand.nextBytes(key);

            AESNativeCFB nativeEnc = new AESNativeCFB();
            nativeEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));


            AESNativeCFB nativeDec = new AESNativeCFB();
            nativeDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

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
                    nCt[t] = nativeEnc.returnByte(msg[t]);
                    jCt[t] = javaEnc.returnByte(msg[t]);
                }

                for (int t = 0; t < lim; t++)
                {
                    nPt[t] = nativeDec.returnByte(nCt[t]);
                    jPt[t] = javaDec.returnByte(jCt[t]);
                }

                TestCase.assertTrue("Key Size: " + keySize + " javaCT = nativeCt", Arrays.areEqual(jCt, nCt));

                if (!Arrays.areEqual(jPt, nPt))
                {
                    System.out.println(Hex.toHexString(jPt));
                    System.out.println(Hex.toHexString(nPt));
                }

                TestCase.assertTrue("Key Size: " + keySize + " javaPt = nativePt", Arrays.areEqual(jPt, nPt));


                TestCase.assertTrue("Key Size: " + keySize + " message = javaPt", Arrays.areEqual(jPt, Arrays.copyOfRange(msg, 0, lim)));
            }
        }
    }


    /**
     * Test every byte length from 0 to 1025 bytes as a stream cipher.
     *
     * @throws Exception
     */
    @Test
    public void testCFBSpread() throws Exception
    {
        if (!TestUtil.hasNativeService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("cbc"))
            {
                TestCase.fail("Skipping CFB spread test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom rand = new SecureRandom();

        for (int keySize : new int[]{16, 24, 32})
        {

            byte[] iv = new byte[16];
            rand.nextBytes(iv);

            byte[] key = new byte[keySize];
            rand.nextBytes(key);

            AESNativeCFB nativeEnc = new AESNativeCFB();
            nativeEnc.init(true, new ParametersWithIV(new KeyParameter(key), iv));


            AESNativeCFB nativeDec = new AESNativeCFB();
            nativeDec.init(false, new ParametersWithIV(new KeyParameter(key), iv));

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


                nativeEnc.processBytes(msg, 0, lim, nCt, 0);
                javaEnc.processBytes(msg, 0, lim, jCt, 0);

                nativeDec.processBytes(nCt, 0, lim, nPt, 0);
                javaDec.processBytes(jCt, 0, lim, jPt, 0);

                TestCase.assertTrue("Key Size: " + keySize + " javaCT = nativeCt", Arrays.areEqual(jCt, nCt));

                if (!Arrays.areEqual(jPt, nPt))
                {
                    System.out.println(Hex.toHexString(jPt));
                    System.out.println(Hex.toHexString(nPt));
                }

                TestCase.assertTrue("Key Size: " + keySize + " javaPt = nativePt", Arrays.areEqual(jPt, nPt));


                TestCase.assertTrue("Key Size: " + keySize + " message = javaPt", Arrays.areEqual(jPt, Arrays.copyOfRange(msg, 0, lim)));
            }
        }
    }

}
