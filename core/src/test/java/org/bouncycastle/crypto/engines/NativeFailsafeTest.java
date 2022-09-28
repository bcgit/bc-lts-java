package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.NativeLoader;
import org.junit.Test;

import static junit.framework.TestCase.fail;

public class NativeFailsafeTest
    extends TestCase
{

    public static final String NATIVE_FAILSAFE_TEST = "test.bcfips.ignore.native";

    @Test
    public void testECB()
    {

        boolean hasECB = NativeLoader.hasHardwareAesECB();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasECB)
        {
            if (skip.contains("ecb"))
            {
                return;
            }
            fail("expected support for native ecb");
        }
    }

    @Test
    public void testCBC()
    {

        boolean hasCBC = NativeLoader.hasHardwareAesCBC();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasCBC)
        {
            if (skip.contains("cbc"))
            {
                return;
            }
            fail("expected support for native cbc");
        }
    }


    @Test
    public void testGCM()
    {

        boolean hasGCM = NativeLoader.hasHardwareAesGCM();

        String skip = System.getProperty(NATIVE_FAILSAFE_TEST, "");

        if (!hasGCM)
        {
            if (skip.contains("gcm"))
            {
                return;
            }
            fail("expected support for native gcm");
        }
    }

}
