package org.bouncycastle.crypto.engines;

import java.util.Enumeration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestFailure;
import junit.framework.TestResult;
import junit.framework.TestSuite;


public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        TestResult res = junit.textui.TestRunner.run(suite());
        if (res.errorCount() > 0)
        {
            Enumeration<TestFailure> e = res.errors();
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement().toString());
            }
        }
        if (res.failureCount() > 0)
        {
            Enumeration<TestFailure> e = res.failures();
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement().toString());
            }
        }

        if (!res.wasSuccessful())
        {
            System.exit(1);
        }
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Native concordance tests");
        suite.addTestSuite(AesCBCConcordanceTest.class);
        suite.addTestSuite(AesCFBConcordanceTest.class);
        suite.addTestSuite(AesECBConcordanceTest.class);
        suite.addTestSuite(AesGCMConcordanceTest.class);

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
