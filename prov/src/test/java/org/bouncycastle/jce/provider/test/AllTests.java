package org.bouncycastle.jce.provider.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCE Tests");

        suite.addTestSuite(SimpleTestTest.class);
        // lives in org.bouncycastle.jce.provider for package access to ReasonsMask, so it is
        // registered from here rather than carrying its own AllTests
        suite.addTestSuite(org.bouncycastle.jce.provider.ReasonsMaskTest.class);

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
