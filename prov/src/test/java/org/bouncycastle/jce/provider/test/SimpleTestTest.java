package org.bouncycastle.jce.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;

import java.security.Security;

public class SimpleTestTest
        extends TestCase
{
    public void testJCE()
    {
        System.setProperty("org.bouncycastle.bks.enable_v1", "true");

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        org.bouncycastle.util.test.Test[] tests = RegressionTest.tests();

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult) tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                System.out.println("Test failed: " + tests[i]);
                fail("index " + i + " " + result.toString());
            }
        }
    }
}
