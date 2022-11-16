package org.bouncycastle;

import java.util.Enumeration;

import junit.framework.TestResult;

public class PrintResults
{
    public static void printResult(TestResult result)
    {
        if (result.failureCount() > 0)
        {
            Enumeration r = result.failures();
            while (r.hasMoreElements())
            {
                System.out.println(r.nextElement());
            }
        }

        if (result.errorCount() > 0)
        {
            Enumeration r = result.errors();
            while (r.hasMoreElements())
            {
                System.out.println(r.nextElement());
            }
        }

        if (!result.wasSuccessful())
        {
            System.exit(1);
        }
    }
}
