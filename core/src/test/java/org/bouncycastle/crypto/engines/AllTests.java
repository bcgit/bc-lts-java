package org.bouncycastle.crypto.engines;

import java.util.Enumeration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestFailure;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import org.bouncycastle.PrintResults;


public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintResults.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Native concordance tests");
        suite.addTestSuite(AesCBCConcordanceTest.class);
        suite.addTestSuite(AesCFBConcordanceTest.class);
        suite.addTestSuite(AesECBConcordanceTest.class);
        suite.addTestSuite(AesGCMConcordanceTest.class);
        suite.addTestSuite(NativeLimitTests.class);

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
