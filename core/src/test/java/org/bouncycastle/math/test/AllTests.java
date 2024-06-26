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
        suite.addTestSuite(MulTest.class);
        suite.addTestSuite(MulLimitTest.class);

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
