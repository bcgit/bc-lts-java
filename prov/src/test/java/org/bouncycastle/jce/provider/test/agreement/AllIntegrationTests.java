package org.bouncycastle.jce.provider.test.agreement;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.test.SimpleTestTest;
import org.bouncycastle.test.PrintTestResult;

import java.security.Security;

public class AllIntegrationTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCE Tests");

       suite.addTestSuite(JavaNativeAgreementTest.class);
       suite.addTestSuite(JavaNativeLargeMessageTest.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            System.setProperty("org.bouncycastle.bks.enable_v1", "true");

            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }

}
