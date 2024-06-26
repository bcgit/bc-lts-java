package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestRandomData;

/**
 * basic test class for the AES cipher vectors from FIPS-197
 */
public class AESTest
        extends BaseBlockCipherTest
{
    static String[] cipherTests =
            {
                    "128",
                    "000102030405060708090a0b0c0d0e0f",
                    "00112233445566778899aabbccddeeff",
                    "69c4e0d86a7b0430d8cdb78070b4c55a",
                    "192",
                    "000102030405060708090a0b0c0d0e0f1011121314151617",
                    "00112233445566778899aabbccddeeff",
                    "dda97ca4864cdfe06eaf70a0ec0d7191",
                    "256",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "00112233445566778899aabbccddeeff",
                    "8ea2b7ca516745bfeafc49904b496089",
            };

    public AESTest()
    {
        super("AES");
    }

    private void test(
            int strength,
            byte[] keyBytes,
            byte[] input,
            byte[] output)
            throws Exception
    {
        Key key;
        Cipher in, out;
        CipherInputStream cIn;
        CipherOutputStream cOut;
        ByteArrayInputStream bIn;
        ByteArrayOutputStream bOut;

        key = new SecretKeySpec(keyBytes, "AES");

        in = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        out = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("AES failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("AES failed initialisation - " + e.toString(), e);
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            fail("AES failed encryption - " + e.toString(), e);
        }

        byte[] bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("AES failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte) dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            fail("AES failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("AES failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    private void eaxTest()
            throws Exception
    {
        byte[] K = Hex.decode("233952DEE4D5ED5F9B9C6D6FF80FF478");
        byte[] N = Hex.decode("62EC67F9C3A4A407FCB2A8C49031A8B3");
        byte[] P = Hex.decode("68656c6c6f20776f726c642121");
        byte[] C = Hex.decode("2f9f76cb7659c70e4be11670a3e193ae1bc6b5762a");

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(K, "AES");

        in = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        out = Cipher.getInstance("AES/EAX/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in EAX");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in EAX");
        }

        try
        {
            in = Cipher.getInstance("AES/EAX/PKCS5Padding", "BC");

            fail("bad padding missed in EAX");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }
    }

    private void ccmTest()
            throws Exception
    {
        byte[] K = Hex.decode("404142434445464748494a4b4c4d4e4f");
        byte[] N = Hex.decode("10111213141516");
        byte[] P = Hex.decode("68656c6c6f20776f726c642121");
        byte[] C = Hex.decode("39264f148b54c456035de0a531c8344f46db12b388");

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(K, "AES");

        in = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        out = Cipher.getInstance("AES/CCM/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in CCM");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in CCM");
        }

        try
        {
            in = Cipher.getInstance("AES/CCM/PKCS5Padding", "BC");

            fail("bad padding missed in CCM");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }
    }

    private void gcmTest()
            throws Exception
    {
        // Test Case 15 from McGrew/Viega
        byte[] K = Hex.decode(
                "feffe9928665731c6d6a8f9467308308"
                        + "feffe9928665731c6d6a8f9467308308");
        byte[] P = Hex.decode(
                "d9313225f88406e5a55909c5aff5269a"
                        + "86a7a9531534f7da2e4c303d8a318a72"
                        + "1c3c0c95956809532fcf0e2449a6b525"
                        + "b16aedf5aa0de657ba637b391aafd255");
        byte[] N = Hex.decode("cafebabefacedbaddecaf888");
        String T = "b094dac5d93471bdec1a502270e3cc6c";
        byte[] C = Hex.decode(
                "522dc1f099567d07f47f37a32a84427d"
                        + "643a8cdcbfe5c0c97598a2bd2555d1aa"
                        + "8cb08e48590dbb3da7b08b1056828838"
                        + "c5f61e6393ba7a0abcc9f662898015ad"
                        + T);

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(K, "AES");

        in = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        out = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in GCM");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in GCM");
        }

        try
        {
            in = Cipher.getInstance("AES/GCM/PKCS5Padding", "BC");

            fail("bad padding missed in GCM");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }


        // reuse test
        in = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        enc = in.doFinal(P);

        try
        {
            in.doFinal(P);
            fail("no exception on reuse");
        }
        catch (IllegalStateException e)
        {
            boolean ok = e.getMessage().equals("GCM cipher cannot be reused for encryption") ||
                    e.getMessage().equals("cannot reuse nonce for GCM encryption"); // packet cipher
            isTrue("wrong message", ok);
        }

        try
        {
            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));
            fail("no exception on reuse");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for GCM encryption"));
        }

        //
        // GCM-SIV
        //
        key = new SecretKeySpec(Hex.decode("01000000000000000000000000000000"), "AES");
        N = Hex.decode("030000000000000000000000");
        P = Hex.decode("01000000000000000000000000000000" + "02000000000000000000000000000000"
                + "03000000000000000000000000000000" + "04000000000000000000000000000000");
        C = Hex.decode("2433668f1058190f6d43e360f4f35cd8" + "e475127cfca7028ea8ab5c20f7ab2af0"
                + "2516a2bdcbc08d521be37ff28c152bba" + "36697f25b4cd169c6590d1dd39566d3f"
                + "8a263dd317aa88d56bdf3936dba75bb8");

        in = Cipher.getInstance("AES/GCM-SIV/NoPadding", "BC");
        out = Cipher.getInstance("AES/GCM-SIV/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in GCM-SIV");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in GCM-SIV");
        }

        try
        {
            in = Cipher.getInstance("AES/GCM-SIV/PKCS5Padding", "BC");

            fail("bad padding missed in GCM");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }

    }

    private void gcmTestWithRandom()
            throws Exception
    {
        byte[] K = Hex.decode(
                "feffe9928665731c6d6a8f9467308308"
                        + "feffe9928665731c6d6a8f9467308308");
        byte[] P = Hex.decode(
                "d9313225f88406e5a55909c5aff5269a"
                        + "86a7a9531534f7da2e4c303d8a318a72"
                        + "1c3c0c95956809532fcf0e2449a6b525"
                        + "b16aedf5aa0de657ba637b391aafd255");

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(K, "AES");

        in = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        out = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new TestRandomData("d0effdb2ec15369ff27a02bff3f800ef"));

        byte[] enc = in.doFinal(P);

        isTrue(Arrays.areEqual(Hex.decode("d0effdb2ec15369ff27a02bf"), in.getIV()));

        isEquals(12, in.getIV().length);

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(in.getIV()));

        byte[] dec = out.doFinal(enc);
        isTrue("plaintext doesn't match in GCM", Arrays.areEqual(P, dec));

        try
        {
            in = Cipher.getInstance("AES/GCM/PKCS5Padding", "BC");

            fail("bad padding missed in GCM");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }
    }

    private void ocbTest()
            throws Exception
    {
        byte[] K = Hex.decode(
                "000102030405060708090A0B0C0D0E0F");
        byte[] P = Hex.decode(
                "000102030405060708090A0B0C0D0E0F");
        byte[] N = Hex.decode("000102030405060708090A0B");
        String T = "4CBB3E4BD6B456AF";
        byte[] C = Hex.decode(
                "BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A" + T);

        Key key;
        Cipher in, out;

        key = new SecretKeySpec(K, "AES");

        in = Cipher.getInstance("AES/OCB/NoPadding", "BC");
        out = Cipher.getInstance("AES/OCB/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in OCB");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in OCB");
        }

        try
        {
            in = Cipher.getInstance("AES/OCB/PKCS5Padding", "BC");

            fail("bad padding missed in OCB");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }
    }


    public void packetCipher() throws Exception
    {
        // Trigger use of packet cipher in test

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }


        if ("true".equals(System.getProperty("org.bouncycastle.test.skip_pc"))) {
            System.out.println("Skipping test on packetCipher");
            return;
        }

        SecureRandom rand = new SecureRandom();

        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] msg = new byte[32];
        byte[] expected = null;

        rand.nextBytes(key);
        rand.nextBytes(iv);
        rand.nextBytes(msg);

        CryptoServicesRegistrar.setNativeEnabled(false);

        // Produce a test vector with the low level api
        CBCModeCipher cbc = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cbc.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        TestCase.assertTrue(cbc.toString().contains("CBC[Java](AES[Java]")); // Must be java version

        expected = new byte[msg.length];
        cbc.processBlocks(msg, 0, 2, expected, 0);

        Cipher javaC = Cipher.getInstance("AES/CBC/NOPADDING", BouncyCastleProvider.PROVIDER_NAME);

        javaC.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        if (isJava8())
        {
            TestCase.assertTrue(getPacketCipherToString(javaC).contains("BlockCipher(CBC[Java](AES[Java]")); //
            // Should be null as not call to do final has occurred.
        }
        byte[] out = new byte[javaC.getOutputSize(msg.length)];
        TestCase.assertEquals(out.length, expected.length);

        javaC.doFinal(msg, 0, msg.length, out, 0);

        if (isJava8())
        {
            TestCase.assertTrue(getPacketCipherToString(javaC).contains("CBC-PS[Java](AES[Java])")); //
        }

        TestCase.assertTrue(Arrays.areEqual(expected, out));


    }


    public void performTest()
            throws Exception
    {

        packetCipher();

        for (int i = 0; i != cipherTests.length; i += 4)
        {
            test(Integer.parseInt(cipherTests[i]),
                    Hex.decode(cipherTests[i + 1]),
                    Hex.decode(cipherTests[i + 2]),
                    Hex.decode(cipherTests[i + 3]));
        }

        byte[] kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] out1 = Hex.decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

        wrapTest(1, "AESWrap", kek1, in1, out1);

        byte[] kek2 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] in2 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] out2 = Hex.decode("7c8798dfc802553b3f00bb4315e3a087322725c92398b9c112c74d0925c63b61");

        wrapTest(2, "AESRFC3211WRAP", kek2, kek2, new FixedSecureRandom(Hex.decode("9688df2af1b7b1ac9688df2a")), in2,
                out2);

        byte[] kek3 = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        byte[] in3 = Hex.decode("c37b7e6492584340bed12207808941155068f738");
        byte[] out3 = Hex.decode("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        wrapTest(3, "AESRFC5649WRAP", kek3, in3, out3);

        String[] oids = {
                NISTObjectIdentifiers.id_aes128_ECB.getId(),
                NISTObjectIdentifiers.id_aes128_CBC.getId(),
                NISTObjectIdentifiers.id_aes128_OFB.getId(),
                NISTObjectIdentifiers.id_aes128_CFB.getId(),
                NISTObjectIdentifiers.id_aes192_ECB.getId(),
                NISTObjectIdentifiers.id_aes192_CBC.getId(),
                NISTObjectIdentifiers.id_aes192_OFB.getId(),
                NISTObjectIdentifiers.id_aes192_CFB.getId(),
                NISTObjectIdentifiers.id_aes256_ECB.getId(),
                NISTObjectIdentifiers.id_aes256_CBC.getId(),
                NISTObjectIdentifiers.id_aes256_OFB.getId(),
                NISTObjectIdentifiers.id_aes256_CFB.getId()
        };

        String[] names = {
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/NoPadding",
                "AES/CFB/NoPadding",
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/NoPadding",
                "AES/CFB/NoPadding",
                "AES/ECB/PKCS7Padding",
                "AES/CBC/PKCS7Padding",
                "AES/OFB/NoPadding",
                "AES/CFB/NoPadding"
        };

        oidTest(oids, names, 4);


        String[] wrapOids = {
                NISTObjectIdentifiers.id_aes128_wrap.getId(),
                NISTObjectIdentifiers.id_aes192_wrap.getId(),
                NISTObjectIdentifiers.id_aes256_wrap.getId(),
        };

        wrapOidTest(wrapOids, "AESWrap");

        wrapOids = new String[]{
                NISTObjectIdentifiers.id_aes128_wrap_pad.getId(),
                NISTObjectIdentifiers.id_aes192_wrap_pad.getId(),
                NISTObjectIdentifiers.id_aes256_wrap_pad.getId()
        };

        wrapOidTest(wrapOids, "AESWrapPad");

        eaxTest();
        ccmTest();
        gcmTest();
        gcmTestWithRandom();
        ocbTest();
    }

    public static void main(
            String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AESTest());
    }


    private static String getPacketCipherToString(Cipher cipher)
    {
        try
        {
            Class cl = cipher.getClass();
            Field f = cl.getDeclaredField("spi");
            f.setAccessible(true);
            Object k = f.get(cipher);
            return k == null ? null : k.toString();

        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

    }

}
