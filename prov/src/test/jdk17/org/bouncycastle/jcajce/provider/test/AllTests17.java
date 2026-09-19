package org.bouncycastle.jcajce.provider.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.test.PrintTestResult;

/**
 * The tests that need a platform API the ordinary test source set cannot see - it compiles at
 * release 8, and javax.crypto.KEM arrived in JDK 21 (backported to 17 at runtime).
 */
public class AllTests17
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JDK 17+ provider tests");

        suite.addTestSuite(MLKEMKemSpiTest.class);

        return suite;
    }
}
