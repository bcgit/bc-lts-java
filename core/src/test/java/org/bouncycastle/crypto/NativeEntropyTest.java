package org.bouncycastle.crypto;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;

public class NativeEntropyTest
    extends TestCase
{

    /**
     * To properly validate an entropy source you need
     * to perform a statistical analysis of the output.
     * <p>
     * This test does not do that, it here to check that it returns something.
     */
    public void testESBasic()
        throws Exception
    {

        NativeLoader.loadDriver();

        if (!CryptoServicesRegistrar.getNativeServices().hasFeature(NativeServices.ENTROPY))
        {
            System.out.println("Skipping testESBasic, no native random: " + NativeLoader.getStatusMessage());
            return;
        }

        NativeEntropySource nes = new NativeEntropySource(1024);
        byte[] entropy1 = nes.getEntropy();
        byte[] entropy2 = nes.getEntropy();

        // Must not be same.
        TestCase.assertFalse(Arrays.areEqual(entropy1, entropy2));

    }

}
