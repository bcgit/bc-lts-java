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

public class SHA256JavaAgreementTest
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


    private byte[] takeDigest(byte[] message, boolean expectNative) throws Exception
    {

        SavableDigest dig = SHA256Digest.newInstance();


        if (expectNative)
        {
            TestCase.assertTrue(dig.toString().contains("SHA256[Native]"));
        } else
        {
            TestCase.assertTrue(dig.toString().contains("SHA256[Java]"));
        }

        byte[] res = new byte[dig.getDigestSize()];
        dig.update(message, 0, message.length);
        dig.doFinal(res, 0);
        return res;
    }


    @Test
    public void testSHA256() throws Exception
    {

        if (!TestUtil.hasNativeService("SHA2"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("sha"))
            {
                TestCase.fail("Skipping SHA2 Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom random = new SecureRandom();

        for (int t = 0; t < 10000; t++)
        {
            byte[] msg = new byte[t];
            random.nextBytes(msg);
            CryptoServicesRegistrar.setNativeEnabled(false);
            byte[] java = takeDigest(msg, false);

            CryptoServicesRegistrar.setNativeEnabled(true);
            byte[] nativeDigest = takeDigest(msg, true);

            TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));

        }

    }


}
