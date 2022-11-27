package org.bouncycastle.crypto.digests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class NativeDigestTests
{

    @Test
    public void testSHA256Empty() throws Exception
    {

        if (!CryptoServicesRegistrar.getNativeServices().hasAnyFeature(NativeServices.SHA2))
        {
            System.out.println("Skipping testESBasic, no native random: " + CryptoServicesRegistrar.getNativeStatus());
            return;
        }

        NativeDigest.SHA256Native dig = new NativeDigest.SHA256Native();
        byte[] res = new byte[dig.getDigestSize()];
        dig.doFinal(res, 0);
        TestCase.assertTrue("Empty Digest result",
                Arrays.areEqual(res, Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")));


    }

}
