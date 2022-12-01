package org.bouncycastle.mail.smime.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.mail.PrintResults;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
        throws Exception
    {
       PrintResults.printResult( junit.textui.TestRunner.run (suite()));
    }
    
    public static Test suite()
        throws Exception
    {
        TestSuite suite= new TestSuite("SMIME tests");

        suite.addTestSuite(NewSMIMESignedTest.class);
        try
        {
            suite.addTestSuite(SignedMailValidatorTest.class);
        } catch (NoClassDefFoundError ignored) {
            // Can be excluded from some jar related tests where the module
            // System prevents loading of test resources in the same package
            // TODO probably move resources.
        }
        suite.addTestSuite(NewSMIMEEnvelopedTest.class);
        suite.addTestSuite(SMIMECompressedTest.class);
        suite.addTestSuite(SMIMEMiscTest.class);
        suite.addTestSuite(SMIMEToolkitTest.class);

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
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
