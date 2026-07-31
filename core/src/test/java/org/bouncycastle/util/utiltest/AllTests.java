package org.bouncycastle.util.utiltest;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("util tests");
        suite.addTestSuite(IPTest.class);
        suite.addTestSuite(BigIntegersTest.class);
        suite.addTestSuite(ArraysTest.class);
        suite.addTestSuite(StringsTest.class);
        suite.addTestSuite(StreamsTest.class);
        suite.addTestSuite(AggregateRuntimeExceptionTest.class);
        // These two are in this package but were not listed here, so they never ran. The build
        // only collects classes matching AllTest*, so a test runs only if a suite names it.
        suite.addTestSuite(IntegersTest.class);
        suite.addTestSuite(LongsTest.class);
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
