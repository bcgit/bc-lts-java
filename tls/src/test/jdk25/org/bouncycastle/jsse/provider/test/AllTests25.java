package org.bouncycastle.jsse.provider.test;

import org.bouncycastle.test.PrintTestResult;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests25
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("JDK25 BCJSSE tests");
        suite.addTestSuite(SSLEngineMRTest.class);
        return suite;
    }
}
