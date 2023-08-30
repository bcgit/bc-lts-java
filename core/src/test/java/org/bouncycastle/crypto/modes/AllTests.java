package org.bouncycastle.crypto.modes;

import org.bouncycastle.test.PrintTestResult;
import junit.framework.Test;
import junit.extensions.TestSetup;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Packet ciphers");
        suite.addTestSuite(AESCBCPacketCipherTest.class);
        suite.addTestSuite(AESCCMPacketCipherTest.class);
        suite.addTestSuite(AESCFBPacketCipherTest.class);
        suite.addTestSuite(AESCTRPacketCipherTest.class);
        suite.addTestSuite(AESGCMSIVPacketCipherTest.class);

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
