package org.bouncycastle.math.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.math.MulLimitTest;
import org.bouncycastle.math.MulTest;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args) 
        throws Exception
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("Math tests");

        suite.addTestSuite(PrimesTest.class);

        // These two live in org.bouncycastle.math and no suite named them, so they never ran.
        // MulLimitTest is the negative-path cover for the native Mul path: negative offsets,
        // null arrays and sizes out of range, which cross the JNI boundary as a jint.
        suite.addTestSuite(MulLimitTest.class);
        suite.addTestSuite(MulTest.class);

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
