package org.bouncycastle.crypto.test;


import junit.framework.TestCase;
import org.junit.Test;

public class ExpectedJVMTest extends TestCase
{
    @Test
    public void testExpectedJVM()
    {
        String actual = System.getProperty("java.version", "!");
        String expected = System.getProperty("org.bouncycastle.expected_jvm", "-");

        boolean ok = actual.startsWith(expected);

        if (!ok)
        {
            System.out.println("Actual: " + actual);
            System.out.println("Expected: " + expected);
        }

        TestCase.assertTrue(ok);
    }
}
