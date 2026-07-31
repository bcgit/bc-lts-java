package org.bouncycastle.math.ec.test;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.math.ec.custom.sec.test.SecP128R1FieldTest;
import org.bouncycastle.math.ec.custom.sec.test.SecP256R1FieldTest;
import org.bouncycastle.math.ec.custom.sec.test.SecP384R1FieldTest;
import org.bouncycastle.math.ec.rfc7748.test.X25519Test;
import org.bouncycastle.math.ec.rfc7748.test.X448Test;
import org.bouncycastle.math.ec.rfc8032.test.Ed25519Test;
import org.bouncycastle.math.ec.rfc8032.test.Ed448Test;
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
        TestSuite suite = new TestSuite("EC Math tests");

        suite.addTestSuite(ECAlgorithmsTest.class);
        suite.addTestSuite(ECPointTest.class);
        suite.addTestSuite(FixedPointTest.class);

        // These seven are in sibling packages under org.bouncycastle.math.ec and no suite named
        // them, so they never ran. The build only collects classes matching AllTest*.
        suite.addTestSuite(SecP128R1FieldTest.class);
        suite.addTestSuite(SecP256R1FieldTest.class);
        suite.addTestSuite(SecP384R1FieldTest.class);
        suite.addTestSuite(X25519Test.class);
        suite.addTestSuite(X448Test.class);
        suite.addTestSuite(Ed25519Test.class);
        suite.addTestSuite(Ed448Test.class);

        return new BCTestSetup(suite);
    }

    static List enumToList(Enumeration en)
    {
        List rv = new ArrayList();

        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }

        return rv;
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
