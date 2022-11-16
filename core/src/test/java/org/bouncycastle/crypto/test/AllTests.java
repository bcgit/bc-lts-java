package org.bouncycastle.crypto.test;

import java.util.Enumeration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestFailure;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import org.bouncycastle.PrintResults;
import org.bouncycastle.crypto.NativeEntropyTests;
import org.bouncycastle.crypto.NativeFailsafeTest;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {

       PrintResults.printResult( junit.textui.TestRunner.run(suite()));


    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight Crypto Tests");

        suite.addTestSuite(SimpleTestTest.class);
        suite.addTestSuite(GCMReorderTest.class);

        try
        {
            suite.addTestSuite(NativeFailsafeTest.class);
            suite.addTestSuite(NativeEntropyTests.class);
        } catch (NoClassDefFoundError ignored) {
        }

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
