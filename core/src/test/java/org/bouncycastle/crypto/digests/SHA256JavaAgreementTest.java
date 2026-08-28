package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.SecureRandom;

public class SHA256JavaAgreementTest extends TestCase
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


    private byte[] takeDigest(byte[] message, boolean expectNative, int jitter) throws Exception
    {

        SavableDigest dig = SHA256Digest.newInstance();


        if (expectNative)
        {
            TestCase.assertTrue(dig.toString().contains("SHA256[Native]"));
        }
        else
        {
            TestCase.assertTrue(dig.toString().contains("SHA256[Java]"));
        }

        byte[] res  = new byte[dig.getDigestSize() + jitter];

        if (message.length > 1)
        {
            dig.update(message, jitter, message.length - jitter);
        }
        else
        {
            dig.update(message, 0, message.length);
        }

        dig.doFinal(res, jitter);
        return res;
    }


    @Test
    public void testSHA256() throws Exception
    {

        if (!TestUtil.hasNativeService("SHA2"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha"))
            {
                TestCase.fail("Skipping SHA2 Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom random = new SecureRandom();

        for (int t = 0; t < 10000; t++)
        {
            for (int j = 0; j < 2; j++)
            {
                byte[] msg = new byte[t];
                random.nextBytes(msg);
                CryptoServicesRegistrar.setNativeEnabled(false);
                byte[] java = takeDigest(msg, false, j);

                CryptoServicesRegistrar.setNativeEnabled(true);
                byte[] nativeDigest = takeDigest(msg, true, j);

                TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));
            }
        }

    }

    /**
     * The native Arm cores hand the caller's buffer straight to hashBlock, so an update at a caller
     * offset makes the block pointer misaligned. Pin that path: sweep the update and output offsets
     * across 0..3 with lengths that guarantee at least one whole block after the offset, and require
     * the native result to match pure java.
     */
    @Test
    public void testSHA256MisalignedCallerOffsets() throws Exception
    {
        if (!TestUtil.hasNativeService("SHA2"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha"))
            {
                TestCase.fail("Skipping SHA256 Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }

        SecureRandom random = new SecureRandom();

        for (int jitter = 0; jitter <= 3; jitter++)
        {
            for (int blocks = 1; blocks <= 4; blocks++)
            {
                for (int extra = 0; extra < 3; extra++)
                {
                    byte[] msg = new byte[jitter + blocks * 64 + extra];
                    random.nextBytes(msg);

                    CryptoServicesRegistrar.setNativeEnabled(false);
                    byte[] java = takeDigest(msg, false, jitter);

                    CryptoServicesRegistrar.setNativeEnabled(true);
                    byte[] nativeDigest = takeDigest(msg, true, jitter);

                    TestCase.assertTrue(
                            "SHA256 java vs native at update/output offset " + jitter
                                    + ", message length " + msg.length,
                            Arrays.areEqual(java, nativeDigest));
                }
            }
        }
    }
}
