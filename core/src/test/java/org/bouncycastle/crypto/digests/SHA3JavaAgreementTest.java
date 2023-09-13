package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.engines.TestUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.processing.SupportedSourceVersion;
import java.security.SecureRandom;

public class SHA3JavaAgreementTest extends TestCase
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


    private byte[] takeDigest(int bitLen, byte[] message, boolean expectNative) throws Exception
    {

        Digest dig = SHA3Digest.newInstance(bitLen);


        if (expectNative)
        {
            TestCase.assertTrue(dig.toString().contains("SHA3[Native]"));
        }
        else
        {
            TestCase.assertTrue(dig.toString().contains("SHA3[Java]"));
        }

        byte[] res = new byte[dig.getDigestSize()];
        dig.update(message, 0, message.length);
        dig.doFinal(res, 0);
        return res;
    }

    public void testAlgoName() throws Exception
    {
        if (!TestUtil.hasNativeService(NativeServices.SHA3))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                TestCase.fail("Skipping SHAKE Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        for (int bitLen : new int[]{224, 256, 384, 512})
        {
            SHA3NativeDigest nd = new SHA3NativeDigest(bitLen);
            SHA3Digest dig = new SHA3Digest(bitLen);

            TestCase.assertEquals(nd.getAlgorithmName(), dig.getAlgorithmName());
        }
    }


    @Test
    public void testSHA3() throws Exception
    {

        if (!TestUtil.hasNativeService("SHA3"))
        {
            if (!System.getProperty("test.bclts.ignore.native", "").contains("sha3"))
            {
                TestCase.fail("Skipping SHA3 Agreement Test: " + TestUtil.errorMsg());
            }
            return;
        }


        SecureRandom random = new SecureRandom();

        for (int bitLen : new int[]{224, 256, 384, 512})
        {

            for (int t = 0; t < 10000; t++)
            {
                byte[] msg = new byte[t];
                random.nextBytes(msg);
                CryptoServicesRegistrar.setNativeEnabled(false);
                byte[] java = takeDigest(bitLen, msg, false);

                CryptoServicesRegistrar.setNativeEnabled(true);
                byte[] nativeDigest = takeDigest(bitLen, msg, true);

                TestCase.assertTrue(Arrays.areEqual(java, nativeDigest));

            }
        }

    }


}
