package org.bouncycastle.crypto.engines;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.NativeEntropyTests;
import org.bouncycastle.crypto.NativeFailsafeTest;
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
        TestSuite suite = new TestSuite("Native concordance tests");
        suite.addTestSuite(AesCBCConcordanceTest.class);
        suite.addTestSuite(AesCFBConcordanceTest.class);
        suite.addTestSuite(AesECBConcordanceTest.class);
        suite.addTestSuite(AesGCMConcordanceTest.class);
        //suite.addTestSuite(NativeLimitTests.class);
        suite.addTestSuite(NativeEntropyTests.class);
        suite.addTestSuite(NativeFailsafeTest.class);
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

        }

        protected void tearDown()
        {

        }
    }
}
