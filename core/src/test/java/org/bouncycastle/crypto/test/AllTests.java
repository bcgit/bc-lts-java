package org.bouncycastle.crypto.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.NativeEntropyTests;
import org.bouncycastle.crypto.NativeFailsafeTest;
import org.bouncycastle.crypto.digests.SHA256NativeDigestTests;
import org.bouncycastle.crypto.digests.SHA384JavaAgreementTest;
import org.bouncycastle.crypto.digests.SHA384NativeDigestTests;
import org.bouncycastle.crypto.digests.SHA512NativeDigestTests;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
       PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight Crypto Tests");

        suite.addTestSuite(SimpleTestTest.class);
        suite.addTestSuite(GCMReorderTest.class);
        suite.addTestSuite(HPKETestVectors.class);

        try
        {
            suite.addTestSuite(NativeFailsafeTest.class);
            suite.addTestSuite(NativeEntropyTests.class);
            suite.addTestSuite(SHA256NativeDigestTests.class);
            suite.addTestSuite(SHA384NativeDigestTests.class);
            suite.addTestSuite(SHA512NativeDigestTests.class);
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
