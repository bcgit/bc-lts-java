package org.bouncycastle.pqc.crypto.slhdsa;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.pqc.crypto.lms.HSSTests;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenTests;
import org.bouncycastle.pqc.crypto.lms.LMSTests;
import org.bouncycastle.pqc.crypto.lms.TypeTests;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SLHDSA Native Limit tests");

        suite.addTestSuite(SlhDSASha256NativeLimitTest.class);

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
